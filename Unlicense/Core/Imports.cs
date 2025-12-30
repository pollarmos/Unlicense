using Gee.External.Capstone.X86;
using Gee.External.Capstone;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    // [데이터 구조] 호출 지점 정보
    public record ImportCallSiteInfo(ulong InstrAddr, int CallSize, bool InstrWasJmp);

    // [데이터 구조] 래퍼(가짜 함수) 정보
    // (instr_addr, call_size, instr_was_jmp, call_dest, ptr_addr)
    public record ImportWrapperInfo(ulong InstrAddr, int CallSize, bool InstrWasJmp, ulong CallDest, ulong? PtrAddr);

    public static class Imports
    {
        private static readonly Logger LOG = new("Imports");

        /// <summary>
        /// 텍스트 섹션을 순회하며 래핑된 임포트 호출(Wrapped Call)이나 점프를 찾습니다.
        /// </summary>
        public static (Dictionary<ulong, List<ImportCallSiteInfo>>, HashSet<ImportWrapperInfo>) FindWrappedImports(
            MemoryRange textSectionRange,
            Dictionary<ulong, Dictionary<string, object>> exportsDict,
            CapstoneX86Disassembler disassembler,
            FridaExec.FridaProcessControll processController)
        {
            var apiToCalls = new Dictionary<ulong, List<ImportCallSiteInfo>>();
            var wrapperSet = new HashSet<ImportWrapperInfo>();

            int ptrSize = processController.PointerSize; // 4 or 8
            bool is64Bit = ptrSize == 8;

            // Data가 null이면 예외를 던지고, 아니면 data 변수에 할당
            byte[] data = textSectionRange.Data ?? throw new ArgumentException("Text section data cannot be null");

            ulong baseAddr = textSectionRange.Base;
            int size = (int)textSectionRange.Size;
            int i = 0;

            while (i < size)
            {
                // 1. 빠른 필터링 (Quick pre-filter)
                // 휴리스틱 함수들을 이용해 의심스러운 패턴이 아니면 스킵
                if (!IsWrappedThunkJmp(data, i) &&
                    !IsWrappedCall(data, i) &&
                    !IsWrappedTailCall(data, i) &&
                    !IsIndirectCall(data, i))
                {
                    i++;
                    continue;
                }

                // 2. 점프 여부 확인 (Call vs Jmp)
                bool instrWasJmp = false;

                // 0xE9 (JMP), 0x90 0xE9 (NOP JMP), 0xFF 0x25 (JMP Ind), TailCall 체크
                if ((data[i] == 0xE9) ||
                    (i + 1 < size && data[i] == 0x90 && data[i + 1] == 0xE9) ||
                    (i + 1 < size && data[i] == 0xFF && data[i + 1] == 0x25) ||
                    IsWrappedTailCall(data, i))
                {
                    instrWasJmp = true;
                }

                // 3. 디스어셈블리 (Capstone)
                ulong instrAddr = baseAddr + (ulong)i;

                // 최대 16바이트 정도만 잘라서 디스어셈블 시도 (속도 최적화)
                int bytesToRead = Math.Min(16, size - i);
                byte[] codeChunk = new byte[bytesToRead];
                Array.Copy(data, i, codeChunk, 0, bytesToRead);

                // 명령어 분석
                // 파이썬의 md.disasm(data, addr)과 유사
                var instructions = disassembler.Disassemble(codeChunk, (long)instrAddr).ToArray();
                if (instructions.Length == 0)
                {
                    i++;
                    continue;
                }

                X86Instruction instruction = instructions[0];
                int callSize = 0;
                X86Operand? op = null;

                // "call" 또는 "jmp" 인지 확인, 혹은 "nop" 뒤에 오는 "call/jmp" 인지 확인
                if (instruction.Mnemonic == "call" || instruction.Mnemonic == "jmp")
                {
                    callSize = instruction.Bytes.Length;
                    op = instruction.Details.Operands.Length > 0 ? instruction.Details.Operands[0] : null;
                }
                else if (instruction.Mnemonic == "nop")
                {
                    // nop이면 다음 명령어 확인
                    if (instructions.Length > 1)
                    {
                        instruction = instructions[1];
                        if (instruction.Mnemonic == "call" || instruction.Mnemonic == "jmp")
                        {
                            callSize = instruction.Bytes.Length; // nop 크기는 제외된 크기일 수 있음 (주의)
                                                                 // 파이썬 로직상 i += callSize + 1 같은 로직이 있으므로, 
                                                                 // 여기서는 instruction.Address - instrAddr + instruction.Bytes.Length 등을 고려해야 할 수도 있으나
                                                                 // 원본 로직을 따라가면 nop 포함 크기가 아니라 실제 명령 크기를 쓰는 것으로 보임.
                                                                 // 단, 루프 진행(i)은 전체 크기만큼 해야 함.

                            // 원본 파이썬 로직 재현: i는 루프 변수. 
                            // 여기서는 call_size만 구하고, 나중에 i += callSize + 1 등으로 점프함.
                            op = instruction.Details.Operands.Length > 0 ? instruction.Details.Operands[0] : null;
                        }
                        else
                        {
                            i++; continue;
                        }
                    }
                    else
                    {
                        i++; continue;
                    }
                }
                else
                {
                    i++; continue;
                }

                if (op == null) { i++; continue; }

                // 4. 목적지 주소 파싱 (Parse destination)
                ulong callDest = 0;
                ulong? ptrAddr = null;

                if (op.Type == X86OperandType.Immediate)
                {
                    // 상대 주소 점프/호출 (E8/E9 등) -> Capstone이 이미 절대 주소로 계산해줌 (Immediate 값)
                    callDest = (ulong)op.Immediate;
                }
                else if (op.Type == X86OperandType.Memory)
                {
                    try
                    {
                        // 메모리 참조 (FF 15, FF 25 등) -> 간접 호출
                        if (!is64Bit) // x86 (32bit)
                        {
                            ptrAddr = (ulong)op.Memory.Displacement;
                            // 메모리에서 실제 목적지 주소 읽기
                            byte[] memData = processController.ReadProcessMemory((UIntPtr)ptrAddr.Value, (UIntPtr)ptrSize);
                            callDest = BitConverter.ToUInt32(memData, 0);
                        }
                        else // x64 (64bit)
                        {
                            // RIP Relative Addressing 계산: 명령어 주소 + 명령어 크기 + 변위(Disp)
                            long disp = op.Memory.Displacement;
                            ptrAddr = (ulong)((long)instruction.Address + instruction.Bytes.Length + disp);

                            byte[] memData = processController.ReadProcessMemory((UIntPtr)ptrAddr.Value, (UIntPtr)ptrSize);
                            callDest = BitConverter.ToUInt64(memData, 0);
                        }
                    }
                    catch (Exception)
                    {
                        // 메모리 읽기 실패 등
                        i++; continue;
                    }
                }
                else
                {
                    i++; continue;
                }

                // 5. 검증 및 분류 (Verify & Classify)

                // 목적지가 .text 섹션 내부라면 -> 정상적인 내부 함수 호출 (패스)
                if (textSectionRange.Contains(callDest))
                {
                    // 단, 이미 알려진 Export(API)라면 기록 (Not wrapped)
                    if (exportsDict.ContainsKey(callDest))
                    {
                        if (!apiToCalls.ContainsKey(callDest))
                            apiToCalls[callDest] = new List<ImportCallSiteInfo>();

                        apiToCalls[callDest].Add(new ImportCallSiteInfo(instrAddr, callSize, instrWasJmp));

                        // 명령어 크기만큼 건너뛰기 (여기서 +1은 원본 파이썬의 로직을 그대로 따름, 휴리스틱 패딩 등을 고려한듯)
                        i += callSize + 1;
                        continue;
                    }

                    // Wrapped인지 확인 (실행 권한이 있는 영역으로 점프하는지)
                    if (IsInExecutableRange(callDest, processController))
                    {
                        wrapperSet.Add(new ImportWrapperInfo(instrAddr, callSize, instrWasJmp, callDest, ptrAddr));
                        i += callSize + 1;
                        continue;
                    }
                }
                else // .text 섹션 외부로 나가는 경우
                {
                    // 이미 알려진 API 주소라면 -> 정상 (Resolved)
                    if (exportsDict.ContainsKey(callDest))
                    {
                        if (!apiToCalls.ContainsKey(callDest))
                            apiToCalls[callDest] = new List<ImportCallSiteInfo>();

                        apiToCalls[callDest].Add(new ImportCallSiteInfo(instrAddr, callSize, instrWasJmp));
                        i += callSize + 1;
                        continue;
                    }

                    // 알려지지 않은 곳인데 실행 가능한 영역(.winlice 등)이라면 -> Wrapper!
                    if (IsInExecutableRange(callDest, processController))
                    {
                        wrapperSet.Add(new ImportWrapperInfo(instrAddr, callSize, instrWasJmp, callDest, ptrAddr));
                        i += callSize + 1;
                        continue;
                    }
                }

                i++;
            }

            return (apiToCalls, wrapperSet);
        }

        // --- Helper Methods (Heuristics) ---

        private static bool IsIndirectCall(byte[] data, int offset)
        {
            // FF 15 : CALL [Memory]
            if (offset + 1 >= data.Length) return false;
            return data[offset] == 0xFF && data[offset + 1] == 0x15;
        }

        private static bool IsWrappedThunkJmp(byte[] data, int offset)
        {
            if (offset > data.Length - 6) return false;

            bool isE9Jmp = data[offset] == 0xE9;
            bool jmpBehind = false;

            // 앞쪽 6바이트 확인 (인덱스 범위 체크)
            if (offset > 6)
            {
                jmpBehind = (data[offset - 5] == 0xE9) || (data[offset - 6] == 0xE9);
            }

            // 복잡한 WinLicense 패턴 매칭
            bool cond1 = isE9Jmp && (data[offset + 6] == 0xE9 || data[offset + 6] == 0x90);
            bool cond2 = isE9Jmp && (data[offset + 5] == 0xCC || data[offset + 5] == 0x90 || data[offset + 5] == 0xE9);
            bool cond3 = (data[offset] == 0x90 && data[offset + 1] == 0xE9);
            bool cond4 = isE9Jmp && jmpBehind;
            // Turbo Delphi style thunk: FF 25 ... 8B C0
            bool cond5 = (data[offset] == 0xFF && data[offset + 1] == 0x25) && (data[offset + 6] == 0x8B || data[offset + 6] == 0xC0);

            return cond1 || cond2 || cond3 || cond4 || cond5;
        }

        private static bool IsWrappedCall(byte[] data, int offset)
        {
            if (offset + 5 >= data.Length) return false;

            // E8 ... 90 (CALL 뒤에 NOP)
            // 90 E8 (NOP 뒤에 CALL)
            return (data[offset] == 0xE8 && data[offset + 5] == 0x90) ||
                   (data[offset] == 0x90 && data[offset + 1] == 0xE8);
        }

        private static bool IsWrappedTailCall(byte[] data, int offset)
        {
            if (offset + 6 >= data.Length) return false;

            bool isCall = data[offset] == 0xE8;

            // CALL 뒤에 INT 3(CC)가 오는지 확인
            return (isCall && data[offset + 5] == 0xCC) ||
                   (isCall && data[offset + 6] == 0xCC) ||
                   (data[offset] == 0x90 && data[offset + 1] == 0xE8 && data[offset + 6] == 0xCC) ||
                   (data[offset] == 0xFF && data[offset + 1] == 0x25 && data[offset + 6] == 0xCC);
        }

        private static bool IsInExecutableRange(ulong address, FridaExec.FridaProcessControll processController)
        {
            // 이 부분은 ProcessController에 FindRangeByAddress 메소드가 있어야 합니다.
            // 더미로 처리하거나, 기존 클래스에 추가해야 합니다.
            var range = processController.FindRangeByAddress(new UIntPtr(address));
            if (range == null) return false;

            // Protection 문자열 (예: "r-x")에서 'x'가 있는지 확인
            // range.Protection은 "rwx" 형태의 문자열이라고 가정
            if (string.IsNullOrEmpty(range.Protection)) return false;

            return range.Protection.Contains("x");
        }
    }

    // --- Dummy / Placeholder Classes ---
    // 기존 코드(WinLicense3.cs 등)에 이 클래스들이 없다면 아래 주석을 해제하고 사용하세요.

    // FridaProcessController에 추가되어야 할 확장 메서드 또는 멤버 더미
    /*
    public partial class FridaProcessControll 
    {
         public MemoryRange FindRangeByAddress(ulong address) { 
             // 실제 구현: 메모리 맵 리스트를 뒤져서 해당 주소가 포함된 범위를 리턴
             return null; 
         }
    }
    */
}
