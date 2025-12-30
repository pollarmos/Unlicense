using System;
using System.Collections.Generic;
using System.Diagnostics;
using UnicornEngine;
using UnicornEngine.Const;

namespace Unlicense.Core
{
    public static class Emulation
    {
        // 전역 페이지 캐시 유지
        private static Dictionary<ulong, byte[]> _pageCache = new Dictionary<ulong, byte[]>();
        private static readonly Logger LOG = new("Emulation");

        private const ulong STACK_MAGIC_RET_ADDR = 0xdeadbeef;
        private const ulong STACK_ADDR_32 = 0xff000000;
        private const ulong STACK_ADDR_64 = 0xff00000000000000;

        public static UIntPtr? ResolveWrappedApi(
            UIntPtr wrapperStartAddr,
            FridaExec.FridaProcessControll processController,
            Dictionary<UIntPtr, Dictionary<string, object>> exports,
            UIntPtr? expectedRetAddr = null)
        {
            bool is64Bit = processController.PointerSize == 8;
            int mode = is64Bit ? Common.UC_MODE_64 : Common.UC_MODE_32;
            int arch = Common.UC_ARCH_X86;

            // 함수 시작 시 1회만 로드
            var exportsCache = exports ?? processController.EnumerateExportedFunctions();

            using var uc = new Unicorn(arch, mode);
            HashSet<ulong> localMappedPages = new HashSet<ulong>(); // 중복 매핑 방지용 필터

            int regSp = is64Bit ? X86.UC_X86_REG_RSP : X86.UC_X86_REG_ESP;
            int regResult = is64Bit ? X86.UC_X86_REG_RAX : X86.UC_X86_REG_EAX;
            ulong stackBase = is64Bit ? STACK_ADDR_64 : STACK_ADDR_32;

            try
            {
                // 환경 설정 (Stack, Magic Return)
                ulong pageSize = (ulong)processController.PageSize;
                ulong magicPageAddr = STACK_MAGIC_RET_ADDR - (STACK_MAGIC_RET_ADDR % pageSize);
                uc.MemMap((long)magicPageAddr, (long)pageSize, Common.UC_PROT_ALL);

                long stackSize = (long)(3 * pageSize);
                ulong stackStart = stackBase + (ulong)stackSize - pageSize;
                uc.MemMap((long)stackBase, stackSize, Common.UC_PROT_READ | Common.UC_PROT_WRITE);

                byte[] magicBytes = is64Bit ? BitConverter.GetBytes(STACK_MAGIC_RET_ADDR) : BitConverter.GetBytes((uint)STACK_MAGIC_RET_ADDR);
                uc.MemWrite((long)stackStart, magicBytes);
                uc.RegWrite(regSp, (long)stackStart);

                if (is64Bit) SetupTebX64(uc, processController);
                else SetupTebX86(uc, processController);

                // 메모리 훅 (Unmapped 처리)
                uc.AddEventMemHook((ucInner, type, address, size, value, userData) =>
                {
                    return HookUnmapped(ucInner, address, processController, localMappedPages);
                }, Common.UC_HOOK_MEM_UNMAPPED, null);

                ulong stopAddr = expectedRetAddr?.ToUInt64() ?? STACK_MAGIC_RET_ADDR;
                long resolvedAddress = -1;

                // 블록 훅 (API 도달 확인)
                uc.AddBlockHook((ucInner, address, size, userData) =>
                {
                    // HookBlock 내부에서는 절대로 Frida 통신(RPC)을 하지 않음
                    var result = HookBlock(ucInner, (ulong)address, exportsCache, stopAddr, is64Bit);
                    if (result.HasValue)
                    {
                        resolvedAddress = (long)result.Value;
                        ucInner.EmuStop();
                    }
                }, null, 1, 0);

                ulong start = wrapperStartAddr.ToUInt64();

                // ★ 핵심: 명령어 실행 수를 5,000개로 제한하여 무한 루프 및 스택 파괴 방지
                uc.EmuStart((long)start, (long)(start + 2048), 0, 5000);

                if (resolvedAddress != -1) return (UIntPtr)resolvedAddress;
                return (UIntPtr)uc.RegRead(regResult);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Emulation Critical Error] {ex.Message}");
                return null;
            }
        }

        private static bool HookUnmapped(Unicorn uc, long address, FridaExec.FridaProcessControll processController, HashSet<ulong> localMappedPages)
        {
            ulong uAddr = (ulong)address;
            if (uAddr == 0) return false;
            ulong pageSize = (ulong)processController.PageSize;
            ulong alignedAddr = uAddr - (uAddr % pageSize);

            // 중복 매핑 시도 자체를 원천 차단
            if (localMappedPages.Contains(alignedAddr)) return true;

            try
            {
                if (_pageCache.TryGetValue(alignedAddr, out byte[] cachedData))
                {
                    try { uc.MemMap((long)alignedAddr, (long)pageSize, Common.UC_PROT_ALL); } catch { }
                    uc.MemWrite((long)alignedAddr, cachedData);
                    localMappedPages.Add(alignedAddr);
                    return true;
                }

                // 캐시 없을 때만 1회 통신
                byte[] data = processController.ReadProcessMemory((UIntPtr)alignedAddr, (UIntPtr)pageSize);
                if (data != null && data.Length > 0)
                {
                    _pageCache[alignedAddr] = data;
                    try { uc.MemMap((long)alignedAddr, (long)pageSize, Common.UC_PROT_ALL); } catch { }
                    uc.MemWrite((long)alignedAddr, data);
                    localMappedPages.Add(alignedAddr);
                    return true;
                }
            }
            catch { }
            return false;
        }

        private static ulong? HookBlock(Unicorn uc, ulong address, Dictionary<UIntPtr, Dictionary<string, object>> exports, ulong stopAddr, bool is64Bit)
        {
            // exportsCache에서 즉시 조회 (통신 0)
            if (exports.TryGetValue((UIntPtr)address, out var apiInfo))
            {
                string apiName = apiInfo.ContainsKey("name") ? (apiInfo["name"]?.ToString() ?? "Unknown") : "Unknown";
                int regSp = is64Bit ? X86.UC_X86_REG_RSP : X86.UC_X86_REG_ESP;
                long sp = uc.RegRead(regSp);

                byte[] retBytes = new byte[is64Bit ? 8 : 4];
                try { uc.MemRead(sp, retBytes); } catch { return null; }

                ulong retAddr = is64Bit ? BitConverter.ToUInt64(retBytes, 0) : BitConverter.ToUInt32(retBytes, 0);

                if (retAddr == stopAddr || retAddr == STACK_MAGIC_RET_ADDR || IsNoReturnApi(apiName))
                    return address;

                // Bogus API 처리 (Sleep 등)
                if (IsBogusApi(apiName))
                {
                    (ulong result, int argCount) = SimulateBogusApi(apiName);
                    uc.RegWrite(is64Bit ? X86.UC_X86_REG_RAX : X86.UC_X86_REG_EAX, (long)result);
                    int ptrSize = is64Bit ? 8 : 4;
                    uc.RegWrite(regSp, sp + (long)(ptrSize * (1 + (is64Bit ? Math.Max(0, argCount - 4) : argCount))));
                    uc.RegWrite(is64Bit ? X86.UC_X86_REG_RIP : X86.UC_X86_REG_EIP, (long)retAddr);
                    return null;
                }
            }
            return null;
        }

        // TEB/PEB 및 보조 함수 생략 (기존 로직 유지)
        private static void SetupTebX86(Unicorn uc, FridaExec.FridaProcessControll pc) { /* ... */ }
        private static void SetupTebX64(Unicorn uc, FridaExec.FridaProcessControll pc) { /* ... */ }
        private static bool IsNoReturnApi(string name) => name == "ExitProcess" || name == "FatalExit" || name == "ExitThread";
        private static bool IsBogusApi(string name) => name == "Sleep";
        private static (ulong, int) SimulateBogusApi(string name) => name == "Sleep" ? (0UL, 1) : (0UL, 0);
    }
}