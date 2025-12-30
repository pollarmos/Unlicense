using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    public static class WinLicense3
    {
        private static readonly Logger LOG = new("WinLicense3");

        public static void FixAndDumpPe(
            FridaExec.FridaProcessControll processController,
            string peFilePath,
            UIntPtr imageBase,
            UIntPtr oep,
            List<MemoryRange> sectionRanges,
            MemoryRange textSectionRange)
        {
            Debug.WriteLine("Looking for the IAT...");
            MemoryRange? iatRange = FindIat(processController, imageBase, sectionRanges, textSectionRange);

            if (iatRange == null)
            {
                Debug.WriteLine("IAT not found");
                return;
            }

            Debug.WriteLine($"IAT found: 0x{iatRange.Base.ToUInt64():X}");

            Debug.WriteLine("Resolving imports ...");
            var unwrapRes = UnwrapIat(iatRange, processController);

            if (unwrapRes == null)
            {
                Debug.WriteLine("IAT unwrapping failed");
                return;
            }

            (int iatSize, int resolvedImportCount) = unwrapRes.Value;
            Debug.WriteLine($"Imports resolved: {resolvedImportCount}");
            Debug.WriteLine($"Fixed IAT size=0x{iatSize:X}");

            Debug.WriteLine($"Dumping PE with OEP=0x{oep.ToUInt64():X} ...");
            DumpUtils.DumpPe(processController, peFilePath, imageBase, oep, iatRange.Base, (uint)iatSize, false);
        }

        private static MemoryRange? FindIat(
            FridaExec.FridaProcessControll processController,
            UIntPtr imageBase,
            List<MemoryRange> sectionRanges,
            MemoryRange textSectionRange)
        {
            var exportsDict = processController.EnumerateExportedFunctions();
            var linearScanResult = FindIatFromDataSections(processController, imageBase, sectionRanges, exportsDict);

            if (linearScanResult != null) return linearScanResult;

            var exportsDictUlong = exportsDict.ToDictionary(k => k.Key.ToUInt64(), v => v.Value);
            return FindIatFromCodeSections(processController, imageBase, textSectionRange, exportsDictUlong);
        }

        private static MemoryRange? FindIatFromDataSections(
            FridaExec.FridaProcessControll processController,
            UIntPtr imageBase,
            List<MemoryRange> sectionRanges,
            Dictionary<UIntPtr, Dictionary<string, object>> exportsDict)
        {
            int pageSize = processController.PageSize;
            foreach (var section in sectionRanges)
            {
                UIntPtr pageAddr = (UIntPtr)(section.Base.ToUInt64());
                byte[] data = processController.ReadProcessMemory(pageAddr, (UIntPtr)pageSize);
                if (data == null || data.Length == 0) continue;

                int? iatStartOffset = FindIatStart(data, exportsDict, processController);
                if (iatStartOffset.HasValue)
                {
                    return new MemoryRange(
                        (UIntPtr)(pageAddr.ToUInt64() + (ulong)iatStartOffset.Value),
                        (UIntPtr)(section.Size.ToUInt64() - (ulong)iatStartOffset.Value),
                        section.Protection
                    );
                }
            }
            return null;
        }

        private static int? FindIatStart(byte[] data, Dictionary<UIntPtr, Dictionary<string, object>> exports, FridaExec.FridaProcessControll processController)
        {
            int pointerSize = processController.PointerSize;
            for (int i = 0; i < data.Length / pointerSize; i++)
            {
                int offset = i * pointerSize;
                if (offset + pointerSize > data.Length) break;
                UIntPtr ptr = (pointerSize == 8) ? (UIntPtr)BitConverter.ToUInt64(data, offset) : (UIntPtr)BitConverter.ToUInt32(data, offset);
                if (exports.ContainsKey(ptr)) return offset;
            }
            return null;
        }

        private static MemoryRange? FindIatFromCodeSections(FridaExec.FridaProcessControll processController, UIntPtr imageBase, MemoryRange textSectionRange, Dictionary<ulong, Dictionary<string, object>> exportsDict)
        {
            var mode = processController.PointerSize == 8 ? X86DisassembleMode.Bit64 : X86DisassembleMode.Bit32;
            using var disassembler = CapstoneDisassembler.CreateX86Disassembler(mode);
            var (apiToCalls, wrapperSet) = Imports.FindWrappedImports(textSectionRange, exportsDict, disassembler, processController);
            if (wrapperSet.Count == 0) return null;
            var ptrPages = wrapperSet.Where(w => w.PtrAddr.HasValue).GroupBy(w => w.PtrAddr!.Value & 0xFFFFF000).OrderByDescending(g => g.Count()).FirstOrDefault();
            if (ptrPages != null) return processController.FindRangeByAddress(new UIntPtr(ptrPages.Key));
            return null;
        }

        // ★ [메모리 폭주 해결 최종 진화형]
        private static (int, int)? UnwrapIat(MemoryRange iatRange, FridaExec.FridaProcessControll processController)
        {
            int pointerSize = processController.PointerSize;
            ulong pageSize = (ulong)processController.PageSize;
            var ranges = processController.EnumerateModuleRanges(processController.MainModuleName);

            // 1. 거대 데이터는 루프 밖에서 딱 1회만 로드
            var cachedExports = processController.EnumerateExportedFunctions();

            // 2. 동적 할당 차단을 위해 고정 크기 버퍼 사용
            byte[] finalIatBuffer = new byte[iatRange.Size.ToUInt64()];
            int bufferOffset = 0;
            int resolvedImportCount = 0;
            int gcCounter = 0;

            for (ulong currentAddr = iatRange.Base.ToUInt64();
                 currentAddr < iatRange.Base.ToUInt64() + iatRange.Size.ToUInt64();
                 currentAddr += pageSize)
            {
                ulong dataRemaining = (iatRange.Base.ToUInt64() + iatRange.Size.ToUInt64()) - currentAddr;
                ulong dataSize = Math.Min(pageSize, dataRemaining);
                byte[] pageData = processController.ReadProcessMemory((UIntPtr)currentAddr, (UIntPtr)dataSize);

                if (pageData == null) continue;

                for (int i = 0; i < pageData.Length; i += pointerSize)
                {
                    if (i + pointerSize > pageData.Length) break;
                    ulong wrapperStart = (pointerSize == 8) ? BitConverter.ToUInt64(pageData, i) : BitConverter.ToUInt32(pageData, i);

                    bool isInMain = ranges.Any(r => wrapperStart >= r.Base.ToUInt64() && wrapperStart < r.Base.ToUInt64() + r.Size.ToUInt64());

                    UIntPtr writeVal = (UIntPtr)wrapperStart;
                    if (isInMain)
                    {
                        var resolvedApi = Emulation.ResolveWrappedApi((UIntPtr)wrapperStart, processController, cachedExports);
                        if (resolvedApi.HasValue)
                        {
                            writeVal = resolvedApi.Value;
                            resolvedImportCount++;
                        }

                        // ★ [임계점 해결] API 10개를 처리할 때마다 강제로 메모리 파괴 및 회수
                        gcCounter++;
                        if (gcCounter >= 10)
                        {
                            GC.Collect();
                            GC.WaitForPendingFinalizers();
                            GC.Collect(); // 잔여 비관리 메모리까지 수거
                            gcCounter = 0;
                        }
                    }

                    // ★ 할당 없이 버퍼에 직접 데이터 복사
                    byte[] ptrBytes = (pointerSize == 8) ? BitConverter.GetBytes(writeVal.ToUInt64()) : BitConverter.GetBytes(writeVal.ToUInt32());
                    if (bufferOffset + pointerSize <= finalIatBuffer.Length)
                    {
                        Buffer.BlockCopy(ptrBytes, 0, finalIatBuffer, bufferOffset, pointerSize);
                        bufferOffset += pointerSize;
                    }
                }
            }

            if (bufferOffset > 0)
            {
                processController.WriteProcessMemory(iatRange.Base, finalIatBuffer);
                return (bufferOffset, resolvedImportCount);
            }
            return null;
        }

        private static UIntPtr ReadPointer(byte[] data, int offset, int size)
        {
            if (offset + size > data.Length) return UIntPtr.Zero;
            return (size == 4) ? (UIntPtr)BitConverter.ToUInt32(data, offset) : (UIntPtr)BitConverter.ToUInt64(data, offset);
        }
    }
}