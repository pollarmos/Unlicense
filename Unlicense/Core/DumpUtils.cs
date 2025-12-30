using AsmResolver;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    public class DumpUtils
    {
        private static readonly Logger LOG = new("DumpUtils");

        public static List<MemoryRange> GetSectionRanges(string peFilePath)
        {
            // 1. 리턴할 빈 리스트 생성
            var sectionRanges = new List<MemoryRange>();
            try 
            {
                // 2. PE 파일 파싱 (lief.parse 대응)
                var binary = PEFile.FromFile(peFilePath);

                foreach(var section in binary.Sections)
                {
                    // 가상 주소와 가상 크기를 가져옴
                    // AsmResolver의 uint(Rva, VirtualSize)를 UIntPtr로 변환하여 생성합니다.
                    var range = new MemoryRange(
                        (UIntPtr)section.Rva,
                        (UIntPtr)section.GetVirtualSize(),
                        "r--"
                    );
                    sectionRanges.Add(range);
                }
            } 
            catch (Exception)
            {
                // 파싱 실패 시 에러 로그 출력
                LOG.Error($"Failed to parse PE '{peFilePath}'");
                return sectionRanges; // 빈 리스트 반환
            }
            return sectionRanges;
        }

        public static List<MemoryRange>? ProbeTextSections(string peFilePath)
        {
            var textSections = new List<MemoryRange>();
            try
            {
                var binary = PEFile.FromFile(peFilePath);
                foreach (var section in binary.Sections)
                {
                    // 1. 섹션 이름 가져오기 및 공백/널 문자 제거
                    string sectionName = section.Name ?? "";
                    string strippedSectionName = sectionName.Replace(" ", "").Replace("\0", "");

                    // 2. 이름 기반 필터링 및 중단 조건
                    // 이름이 비어있지 않고, .text / .textbss / .textidx 가 아니면 루프를 중단(break)합니다.
                    if (strippedSectionName.Length > 0)
                    {
                        var allowedNames = new List<string> { ".text", ".textbss", ".textidx" };
                        if (!allowedNames.Contains(strippedSectionName))
                        {
                            break; // 파이썬의 break 로직 재현
                        }
                    }

                    // 3. 실행 권한(MEM_EXECUTE) 확인
                    if (section.IsMemoryExecute)
                    {
                        // 로그 출력
                        LOG.Debug($"Probed .text section at (0x{section.Rva:x}, 0x{section.GetVirtualSize():x})");

                        // MemoryRange 객체 추가 (권한은 "r-x")
                        textSections.Add(new MemoryRange(
                            (UIntPtr)section.Rva,
                            (UIntPtr)section.GetVirtualSize(),
                            "r-x"
                        ));
                    }

                }
            }
            catch (Exception) 
            {
                // 파싱 실패 시 에러 로그 출력
                LOG.Error($"Failed to parse PE '{peFilePath}'");
                return null; 
            }
            return textSections.Count > 0 ? textSections : null;
        }

        /// <summary>
        /// (Python: dump_pe) Scylla 대신 직접 메모리를 읽어서 파일을 재구성합니다.
        /// </summary>
        public static bool DumpPe(
            FridaExec.FridaProcessControll processController,
            string peFilePath,
            UIntPtr imageBase,
            UIntPtr oep,
            UIntPtr iatAddr,
            UIntPtr iatSize,
            bool fixImports)
        {
            string outputFileName = $"unpacked_{Path.GetFileName(peFilePath)}";
            string outputPath = Path.Combine(Path.GetDirectoryName(peFilePath) ?? "", outputFileName);

            LOG.Info($"Dumping PE to '{outputFileName}'...");

            try
            {
                // 1. 원본 파일을 복사해서 베이스로 삼음 (Overlay 데이터 보존 등 유리)
                File.Copy(peFilePath, outputPath, true);

                // 2. AsmResolver로 파일 열기
                var peFile = PEFile.FromFile(outputPath);

                // 3. 헤더 정보 수정
                // ImageBase 수정
                peFile.OptionalHeader.ImageBase = imageBase.ToUInt64();

                // OEP 수정 (OEP - ImageBase = RVA)
                peFile.OptionalHeader.AddressOfEntryPoint = (uint)(oep.ToUInt64() - imageBase.ToUInt64());

                // 4. 각 섹션 데이터를 메모리에서 읽어와 덮어쓰기
                foreach (var section in peFile.Sections)
                {
                    ulong sectionRva = section.Rva;
                    ulong sectionSize = section.GetVirtualSize();

                    if (sectionSize == 0) continue;

                    // 메모리 주소 = ImageBase + RVA
                    UIntPtr memAddress = (UIntPtr)(imageBase.ToUInt64() + sectionRva);

                    // Frida로 메모리 읽기
                    byte[] data = processController.ReadProcessMemory(memAddress, (UIntPtr)sectionSize);

                    if (data != null && data.Length > 0)
                    {
                        // 섹션 내용 교체
                        section.Contents = new DataSegment(data);
                    }
                }

                // 5. 파일 저장 (Builder가 작동하며 PE 구조 재정렬)
                peFile.Write(outputPath);

                // 6. 후처리 (ASLR 제거, 섹션 이름 복구, 사이즈 조정)
                FixPe(outputPath, outputPath); // 덮어쓰기

                LOG.Info($"Output file has been saved at '{outputFileName}'");
                return true;
            }
            catch (Exception ex)
            {
                LOG.Error($"Failed to dump PE: {ex.Message}");
                return false;
            }
        }

        // (Python: dump_dotnet_assembly) - 로직은 DumpPe와 유사하지만 .NET 특화 가능성 있음
        public static bool DumpDotNetAssembly(
            FridaExec.FridaProcessControll processController,
            UIntPtr imageBase)
        {
            // 현재 구조상 DumpPe를 그대로 호출해도 큰 문제는 없습니다.
            // 필요하다면 .NET 메타데이터 헤더 수정 로직이 추가되어야 합니다.
            LOG.Warning("DumpDotNetAssembly is using generic DumpPe logic.");
            return DumpPe(processController, processController.MainModuleName, imageBase, UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero, false);
        }

        // (Python: _fix_pe)
        private static void FixPe(string inputPath, string outputPath)
        {
            // 파이썬처럼 임시 파일을 쓸 수도 있지만, 여기서는 직접 처리 후 저장
            RebuildPe(inputPath, outputPath);
            ResizePe(outputPath, outputPath);
        }

        // (Python: _rebuild_pe)
        private static void RebuildPe(string inputPath, string outputPath)
        {
            var peFile = PEFile.FromFile(inputPath);

            // 섹션 이름 복구 (.rsrc, .text 등)
            ResolveSectionNames(peFile);

            // Disable ASLR (Relocs Stripped, DynamicBase Removed)
            peFile.FileHeader.Characteristics |= AsmResolver.PE.File.Headers.Characteristics.RelocsStripped;
            peFile.OptionalHeader.DllCharacteristics &= ~AsmResolver.PE.File.Headers.DllCharacteristics.DynamicBase;

            // 저장 (AsmResolver는 DOS Stub, Overlay 등을 자동으로 처리해줌)
            peFile.Write(outputPath);
        }

        // (Python: _resolve_section_names)
        private static void ResolveSectionNames(PEFile peFile)
        {
            // 1. Resource Directory 확인 -> .rsrc
            var dataDirs = peFile.OptionalHeader.DataDirectories;
            if (dataDirs.Count > (int)DataDirectoryIndex.ResourceDirectory)
            {
                var rsrcDir = dataDirs[(int)DataDirectoryIndex.ResourceDirectory];
                if (rsrcDir.IsPresentInPE)
                {
                    var section = peFile.GetSectionContainingRva(rsrcDir.VirtualAddress);
                    if (section != null)
                    {
                        LOG.Debug($".rsrc section found (RVA=0x{section.Rva:X})");
                        section.Name = ".rsrc";
                    }
                }
            }

            // 2. EntryPoint 확인 -> .text
            uint epRva = peFile.OptionalHeader.AddressOfEntryPoint;
            if (epRva != 0)
            {
                var section = peFile.GetSectionContainingRva(epRva);
                if (section != null)
                {
                    LOG.Debug($".text section found (RVA=0x{section.Rva:X})");
                    section.Name = ".text";
                }
            }
        }

        // (Python: _resize_pe, _get_pe_size)
        private static void ResizePe(string inputPath, string outputPath)
        {
            long? peSize = GetPeSize(inputPath);
            if (peSize == null) return;

            // 파일 복사 및 자르기
            if (inputPath != outputPath)
            {
                File.Copy(inputPath, outputPath, true);
            }

            using (var fs = new FileStream(outputPath, FileMode.Open, FileAccess.Write))
            {
                if (fs.Length > peSize.Value)
                {
                    fs.SetLength(peSize.Value);
                }
            }
        }

        private static long? GetPeSize(string peFilePath)
        {
            try
            {
                var peFile = PEFile.FromFile(peFilePath);
                if (peFile.Sections.Count == 0) return null;

                // 가장 마지막에 위치한 섹션을 찾음 (Offset + Size가 가장 큰 것)
                // AsmResolver의 Section은 Offset 정보를 가지고 있습니다 (PointerToRawData)

                long maxEnd = 0;
                foreach (var section in peFile.Sections)
                {
                    long end = (long)(section.Offset + section.GetPhysicalSize());
                    if (end > maxEnd) maxEnd = end;
                }

                // 파이썬 로직: highest_section.offset + highest_section.size
                // 오버레이가 있다면 오버레이까지 포함해야 하지만, 
                // AsmResolver로 Rebuild하면 섹션들이 정렬되므로 이 방식이 안전합니다.

                return maxEnd;
            }
            catch
            {
                return null;
            }
        }

        // (Python: pointer_size_to_fmt) - C#에서는 필요 없을 수 있으나 호환성을 위해 남김
        public static int PointerSizeToBytes(int pointerSize)
        {
            if (pointerSize == 4) return 4;
            if (pointerSize == 8) return 8;
            throw new NotSupportedException("Platform not supported");
        }

        public static bool InterpreterCanDumpPE(string peFilePath)
        {
            var currentPlatform = Environment.Is64BitOperatingSystem; // true AMD64

            var binary = PEFile.FromFile(peFilePath);
            var peArchitecture = binary.FileHeader.Machine;

            if (currentPlatform) // 64비트 OS
            {
                if (Environment.Is64BitProcess) // x64 빌드
                {
                    // 64비트 툴은 64비트(AMD64)와 32비트(I386) 타겟 모두 덤프 가능
                    return peArchitecture == MachineType.Amd64 || peArchitecture == MachineType.I386;
                }
                else // x32 빌드
                {
                    return peArchitecture == MachineType.I386;
                }
            }
            else // 32비트 OS 환경인 경우
            {
                // 대상이 32비트여야만 가능
                return peArchitecture == MachineType.I386;
            }
        }

    }
}
