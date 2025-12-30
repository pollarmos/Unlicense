using Gee.External.Capstone.X86;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Hashing;

namespace Unlicense.Core
{
    public static class FunctionHashing
    {
        private static readonly Logger LOG = new("FunctionHashing");
        private const int BB_MAX_SIZE = 0x600;

        // 빈 함수 해시값 (초기값)
        // Python: int(xxhash.xxh32().digest().hex(), 16) -> 0x02CC5D05 (Seed 0 기준)
        public static readonly uint EMPTY_FUNCTION_HASH;

        static FunctionHashing()
        {
            var xxHash = new XxHash32();
            EMPTY_FUNCTION_HASH = BitConverter.ToUInt32(xxHash.GetCurrentHash());
        }

        public static uint ComputeFunctionHash(
            CapstoneX86Disassembler disassembler,
            ulong functionStartAddr,
            Func<ulong, int, byte[]> getDataCallback,
            FridaExec.FridaProcessControll processController)
        {
            // XxHash32 인스턴스 생성
            var xxHash = new XxHash32();

            bool retReached = false;
            ulong basicBlockAddr = functionStartAddr;
            ulong prevBasicBlockAddr = 0;
            HashSet<ulong> visitedAddresses = new HashSet<ulong>();

            while (!retReached)
            {
                if (prevBasicBlockAddr == basicBlockAddr)
                {
                    LOG.Debug("Not a new basic block, aborting");
                    break;
                }
                prevBasicBlockAddr = basicBlockAddr;

                // 메모리 읽기 (콜백 사용)
                byte[] codeData = getDataCallback(basicBlockAddr, BB_MAX_SIZE);
                if (codeData == null || codeData.Length == 0) break;

                // 디스어셈블리
                var instructions = disassembler.Disassemble(codeData, (long)basicBlockAddr);

                foreach (var instruction in instructions)
                {
                    long addr = instruction.Address;
                    visitedAddresses.Add((ulong)addr);

                    string mnemonic = instruction.Mnemonic;

                    // 흐름 제어 및 해싱 로직
                    if (mnemonic == "ret")
                    {
                        retReached = true;
                        HashInstruction(xxHash, instruction, processController);
                        break;
                    }
                    else if (mnemonic == "call")
                    {
                        var op = instruction.Details.Operands.Length > 0 ? instruction.Details.Operands[0] : null;
                        if (op != null && op.Type == X86OperandType.Immediate)
                        {
                            // 파일 매핑 내부에 없는 곳으로의 call은 따라가지 않음 (외부 API 호출 등)
                            if (!IsInFileMapping((ulong)op.Immediate, processController))
                            {
                                basicBlockAddr = (ulong)op.Immediate;
                                break; // 다음 블록으로 이동
                            }
                        }
                        // 그 외의 call은 해싱하고 계속 진행
                        HashInstruction(xxHash, instruction, processController);
                    }
                    else if (mnemonic.StartsWith("j")) // jmp, je, jne ...
                    {
                        var op = instruction.Details.Operands.Length > 0 ? instruction.Details.Operands[0] : null;
                        if (op != null && op.Type == X86OperandType.Immediate)
                        {
                            if (mnemonic == "jmp")
                            {
                                if (visitedAddresses.Contains((ulong)op.Immediate))
                                {
                                    LOG.Debug("Loop detected, aborting");
                                    retReached = true;
                                    HashInstruction(xxHash, instruction, processController);
                                }
                                else
                                {
                                    basicBlockAddr = (ulong)op.Immediate;
                                }
                                break; // 루프 탈출 또는 점프
                            }
                            else
                            {
                                // 조건부 점프(je, jne 등)는 흐름을 따라가지 않고 현재 블록 종료로 처리
                                retReached = true;
                                HashInstruction(xxHash, instruction, processController);
                                break;
                            }
                        }
                        else
                        {
                            // 간접 점프 (jmp rax 등)
                            retReached = true;
                            HashInstruction(xxHash, instruction, processController);
                            break;
                        }
                    }
                    else
                    {
                        // 일반 명령어 해싱
                        HashInstruction(xxHash, instruction, processController);
                    }
                }
            }

            // 최종 해시값 반환 (Big Endian/Little Endian 주의 - 여기선 BitConverter 기본 사용)
            // 파이썬 digest().hex()를 int로 변환한 값과 맞추려면 리틀 엔디안으로 해석
            return BitConverter.ToUInt32(xxHash.GetCurrentHash());
        }

        private static void HashInstruction(XxHash32 hasher, X86Instruction instruction, FridaExec.FridaProcessControll processController)
        {
            // Themida의 Mutation에 영향을 받지 않는 요소만 골라서 문자열로 만듬
            string? val = null;
            string mnemonic = instruction.Mnemonic;
            var operands = instruction.Details.Operands;

            if (mnemonic == "call")
            {
                var op = operands[0];
                if (op.Type == X86OperandType.Immediate && IsInFileMapping((ulong)op.Immediate, processController))
                {
                    val = $"{mnemonic},{op.Immediate:x}";
                }
                else if (op.Type == X86OperandType.Memory && IsInFileMapping((ulong)op.Memory.Displacement, processController))
                {
                    // 세그먼트, 베이스, 인덱스, 오프셋 등 전체 구조 해싱
                    val = $"{mnemonic},{op.Memory.Segment:x},{op.Memory.Base:x},{op.Memory.Index:x},{op.Memory.Displacement:x}";
                }
            }
            else if (mnemonic == "push")
            {
                var op = operands[0];
                // PUSH IMM (Size 2 checking in python logic? Usually check operand size)
                // 파이썬: instruction.size == 2 check. Capstone 바이트 길이 체크.
                if (instruction.Bytes.Length == 2 && op.Type == X86OperandType.Immediate)
                {
                    val = $"{mnemonic},{op.Immediate:x}";
                }
            }
            else if (mnemonic == "mov")
            {
                for (int i = 0; i < operands.Length; i++)
                {
                    var op = operands[i];
                    if (op.Type == X86OperandType.Memory)
                    {
                        // ID 확인 필요
                        // Unicorn 상수 매핑 필요. 여기선 간단히 로직 구현
                        // (op.value.mem.base != UC_X86_REG_ESP && op.value.mem.disp != 0)
                        bool isFsGs = op.Memory.Segment.Id == X86RegisterId.X86_REG_FS || op.Memory.Segment.Id == X86RegisterId.X86_REG_GS; 

                        // Register ID 매핑은 라이브러리마다 다르므로 주의. 
                        // 여기선 Capstone ID를 그대로 씁니다.
                        bool baseNotEsp = op.Memory.Base.Id != X86RegisterId.X86_REG_ESP && op.Memory.Base.Id != X86RegisterId.X86_REG_RSP;

                        if (isFsGs || (baseNotEsp && op.Memory.Displacement != 0))
                        {
                            val = $"{mnemonic},{i},{op.Memory.Segment:x},{op.Memory.Base:x},{op.Memory.Index:x},{op.Memory.Displacement:x}";
                            UpdateHash(hasher, val); // 루프 내부에서 업데이트
                            val = null; // 아래 공통 업데이트 방지
                        }
                    }
                }
            }
            else if (mnemonic == "jmp")
            {
                var op = operands[0];
                if (op.Type == X86OperandType.Memory && IsInFileMapping((ulong)op.Memory.Displacement, processController))
                {
                    val = $"{mnemonic},{op.Memory.Displacement:x}";
                }
            }
            else if (mnemonic == "and" || mnemonic == "cmp" || mnemonic == "xor")
            {
                for (int i = 0; i < operands.Length; i++)
                {
                    var op = operands[i];
                    if (op.Type == X86OperandType.Memory)
                    {
                        if (op.Memory.Base.Id != X86RegisterId.X86_REG_ESP && op.Memory.Base.Id != X86RegisterId.X86_REG_RSP)
                        {
                            val = $"{mnemonic},{i},{op.Memory.Base:x},{op.Memory.Displacement:x}";
                            UpdateHash(hasher, val);
                            val = null;
                        }
                    }
                }
            }
            else if (mnemonic == "shl" || mnemonic == "shr")
            {
                if (operands.Length > 1)
                {
                    var rop = operands[1];
                    if (rop.Type == X86OperandType.Immediate)
                    {
                        val = $"{mnemonic},{rop.Immediate:x}";
                    }
                }
            }
            else if (mnemonic == "ret")
            {
                if (operands.Length == 0)
                    val = $"{mnemonic}";
                else
                    val = $"{mnemonic},{operands[0].Immediate:x}";
            }
            else if (new[] { "fld", "fldz", "fstp", "fcompp", "div", "mul" }.Contains(mnemonic))
            {
                // op_str은 Capstone이 만들어주는 문자열
                val = $"{mnemonic},{instruction.Operand}";
            }

            if (val != null)
            {
                UpdateHash(hasher, val);
            }
        }

        private static void UpdateHash(XxHash32 hasher, string val)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(val);
            hasher.Append(bytes);
        }

        private static bool IsInFileMapping(ulong address, FridaExec.FridaProcessControll processController)
        {
            if (address < 4096) return false;
            // processController에 FindModuleByAddress 구현 필요
            return processController.FindModuleByAddress(new UIntPtr(address)) != null;
        }
    }
}
