using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    public class Application
    {
        public bool Verbose { get; set; } = false;
        public bool PauseOnOep { get; set; } = false;
        public bool NoImports { get; set; } = false;
        public int? ForceOep { get; set; } = null;
        public int? TargetVersion { get; set; } = null;
        public int Timeout { get; set; } = 10;

        public static readonly int[] SUPPORTED_VERSIONS = [2, 3];

        // 파이썬의 LOG = logging.getLogger("unlicense") 대응
        private static readonly Logger LOG = new("unlicense");

        public static void RunUnlicense(
            string peToDump,             // 언패킹 파일이름
            bool verbose = false,        // 디버그 로그 출력
            bool pauseOnOep = false,     // OEP 멈춤
            bool noImports = false,      // Import 
            int? forceOep = null,        // OEP 주소 입력시
            int? targetVersion = null,   // 타겟 버전 선택(2, 3)
            int timeout = 10)            // 기본값 10초
        {
            LogManager.SetupLogger(LOG, verbose);
            ForceRunAsInvoker();
            var pePath = new System.IO.FileInfo(peToDump);
            if (!pePath.Exists)
            {
                LOG.Error($"'{pePath.FullName}' isn't a file or doesn't exist");
                return;
            }

            // 더미다 버전이 지정되지 않은 경우 버전 확인
            if (targetVersion == null)
            {
                // VersionDetection 클래스의 정적 메서드를 호출한다고 가정
                targetVersion = VersionDetection.DetectWinlicenseVersion(peToDump);
                if (targetVersion == null)
                {
                    Debug.WriteLine("Failed to automatically detect packer version");
                    return;
                }
            }
            // 지원하는 버전이 있는지 확인 (2, 3)
            else if (!SUPPORTED_VERSIONS.Contains(targetVersion.Value)) 
            {
                Debug.WriteLine($"Target version '{targetVersion}' is not supported");
                return;
            }
            LOG.Info($"Detected packer version: {targetVersion}.x");

            // PE파일 Machine값과 빌드(x32/x64) 일치확인
            if (!DumpUtils.InterpreterCanDumpPE(peToDump))
            {
                Debug.WriteLine("Target PE cannot be dumped with this application. This is most likely a 32 vs 64 bit mismatch.");
                return;
            }

            // 전체 섹션 범위를 가져옵니다.
            List<MemoryRange> sectionRanges = DumpUtils.GetSectionRanges(peToDump);
            // .text 섹션(실행 코드 영역)의 범위를 별도로 탐지합니다.
            List<MemoryRange>? textSectionRanges = DumpUtils.ProbeTextSections(peToDump);
          
            // .text 섹션 탐지 실패 시 에러 처리
            if (textSectionRanges == null || textSectionRanges.Count == 0)
            {
                Debug.WriteLine("Failed to automatically detect .text section");
                return;
            }

            UIntPtr dumpedImageBase = UIntPtr.Zero;
            UIntPtr dumpedOep = UIntPtr.Zero;
            bool isDotnet = false;

            // 1. OEP 도달 이벤트를 위한 동기화 객체 생성 (Python: oep_reached = threading.Event())
            using var oepReachedEvent = new System.Threading.ManualResetEvent(false);

            // 2. 콜백 함수 정의 (로컬 함수 사용)
            // Python: def notify_oep_reached(...)
            OepReachedCallback notifyOepReached = (baseAddr, oep, dotnet) =>
            {
                // 외부 변수 캡처 및 업데이트
                dumpedImageBase = (UIntPtr)baseAddr;
                dumpedOep = (UIntPtr)oep;
                isDotnet = dotnet;

                // 이벤트 신호 발생 (Wait 해제)
                oepReachedEvent.Set();
            };

            FridaExec.FridaProcessControll? processController = null;
            try
            {
                // 3. 프로세스 실행 및 Frida 스크립트 주입 (Python: process_controller = frida_exec.spawn_and_instrument(...))
                processController = FridaExec.SpawnAndInstrument(
                    peToDump,
                    textSectionRanges,
                    notifyOepReached
                );

                // 4. OEP 도달 대기 (Python: if not oep_reached.wait(float(timeout)):)
                // WaitOne은 신호를 받으면 true, 타임아웃되면 false를 반환합니다.
                if (!oepReachedEvent.WaitOne(TimeSpan.FromSeconds(timeout)))
                {
                    Debug.WriteLine("Original entry point wasn't reached before timeout");
                    return; // sys.exit(4) 대응
                }

                // Section 주소 VA로 변환시작
                ulong baseAddr = dumpedImageBase.ToUInt64(); // e.g., 0x400000

                // 1. Correct .text section ranges (0x1000 -> 0x401000)
                if (textSectionRanges != null)
                {
                    foreach (var range   in textSectionRanges)
                    {
                        range.Base = (UIntPtr)(baseAddr + range.Base.ToUInt64());
                    }
                }

                // 2. Correct all section ranges (0x1000 -> 0x401000, etc.)
                if (sectionRanges != null)
                {
                    foreach (var range in sectionRanges)
                    {
                        range.Base = (UIntPtr)(baseAddr + range.Base.ToUInt64());
                    }
                }
                // VA 변환 끝

                Debug.WriteLine($"OEP reached: OEP=0x{dumpedOep.ToUInt64():X} BASE=0x{dumpedImageBase.ToUInt64():X} DOTNET={isDotnet}");

                // 5. 옵션 처리: Pause on OEP
                if (pauseOnOep)
                {
                    Console.WriteLine("Thread blocked, press ENTER to proceed with the dumping.");
                    Console.ReadLine();
                }

                // 6. 옵션 처리: Force OEP
                if (forceOep.HasValue)
                {
                    // Python: dumped_oep = dumped_image_base + force_oep
                    ulong newOep = dumpedImageBase.ToUInt64() + (ulong)forceOep.Value;
                    dumpedOep = (UIntPtr)newOep;
                    Debug.WriteLine($"Using given OEP RVA value instead (0x{forceOep.Value:X})");
                }

                // 7. OEP가 포함된 Text 섹션 찾기
                MemoryRange textSectionRange = textSectionRanges[0];
                // RVA(상대 주소) 계산
                ulong oepRva = dumpedOep.ToUInt64() - dumpedImageBase.ToUInt64();

                foreach (var range in textSectionRanges)
                {
                    // MemoryRange에 Contains 메소드가 있다고 가정 (없다면: oepRva >= range.Base && oepRva < range.Base + range.Size)
                    if (range.Contains(oepRva))
                    {
                        textSectionRange = range;
                        // 파이썬은 break 없이 루프를 다 돌며 마지막 일치 항목을 쓰거나, 
                        // 일반적으로 하나만 매칭되므로 여기서 멈춰도 무방합니다.
                    }
                }

                // 8. 덤프 수행 (각 클래스는 추후 구현 필요)
                if (isDotnet)
                {
                    Debug.WriteLine("Dumping .NET assembly ...");
                    // if (!DumpDotNetAssembly(processController, dumpedImageBase)) ...
                    Debug.WriteLine(".NET dumping logic is not implemented yet.");
                }
                else if (noImports)
                {
                    // DumpPE(...)
                    Debug.WriteLine("Dumping PE without imports...");
                }
                else if (targetVersion == 2)
                {
                    // WinLicense2.FixAndDumpPe(...)
                    Debug.WriteLine("Starting WinLicense 2.x dumping...");
                }
                else if (targetVersion == 3)
                {
                    // WinLicense3 모듈 호출
                    // 파이썬: winlicense3.fix_and_dump_pe(process_controller, pe_to_dump, ...)
                    WinLicense3.FixAndDumpPe(
                        processController,
                        peToDump,           // 덤프될 파일 경로 (string)
                        dumpedImageBase,    // Image Base (UIntPtr)
                        dumpedOep,          // OEP (UIntPtr)
                        sectionRanges,      // 섹션 목록 (List<MemoryRange>)
                        textSectionRange    // 텍스트 섹션 정보 (MemoryRange)
                    );
                    Debug.WriteLine("Starting WinLicense 3.x dumping...");
                }
            }
            finally
            {
                // 9. 프로세스 종료 및 정리 (Python: finally: process_controller.terminate_process())
                processController?.TerminateProcess();
            }


        }

        /// <summary>
        /// 자식 프로세스가 관리자 권한 승인 없이 현재 권한으로 실행되도록 강제합니다.
        /// </summary>
        private static void ForceRunAsInvoker()
        {
            // 파이썬의 os.environ["__COMPAT_LAYER"] = "RUNASINVOKER"와 동일합니다.
            Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RUNASINVOKER");
        }

    }
}
