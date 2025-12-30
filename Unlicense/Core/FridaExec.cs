using Frida;
using Frida.Data;
using System.Diagnostics;
using System.IO;
using System.Text.Json;


namespace Unlicense.Core
{
    // 파이썬의 OepReachedCallback 대응
    public delegate void OepReachedCallback(long @base, long oep, bool isDotNet);

    public static class FridaExec 
    {
        private static readonly Logger LOG = new("FridaExec");

        public class FridaProcessControll : ProcessControl
        {
            private const long MAX_DATA_CHUNK_SIZE = 64 * 1024 * 1024; //
            private readonly FridaSession _fridaSession;
            private readonly FridaScript _fridaScript;
            private readonly ScriptRpcClient _fridaRpc;

            public FridaProcessControll(
                int pid,
                string mainModuleName,
                FridaSession session,
                FridaScript script,
                ScriptRpcClient rpcClient, // [추가] RpcClient 주입
                Architecture arch,   // [변경] 문자열 대신 변환된 열거형 받기
                int pointerSize,     // [변경] RPC 결과값 직접 받기
                int pageSize)        // [변경] RPC 결과값 직접 받기
            : base(pid, mainModuleName, arch, pointerSize, pageSize)
            {
                _fridaSession = session;
                _fridaScript = script;
                _fridaRpc = rpcClient;
            }

            public override Dictionary<string, object>? FindModuleByAddress(UIntPtr address)
            {
                try
                {
                    return _fridaRpc.CallAsync<Dictionary<string, object>>(
                        "findModuleByAddress",
                        address
                    ).GetAwaiter().GetResult();
                }
                catch { return null; }
            }

            public override MemoryRange? FindRangeByAddress(UIntPtr address, bool includeData = false)
            {
                try
                {
                    var result = _fridaRpc.CallAsync<MemoryRange>(
                        "findRangeByAddress",
                        address,
                        includeData
                    ).GetAwaiter().GetResult();

                    // [★ 로그 추가] 결과가 왔을 때 Protection 값이 정확히 무엇인지 출력
                    if (result != null)
                    {
                        // 이 로그가 콘솔에 "Raw Protection: ---" 라고 찍히는지, 아니면 "NULL"인지, "r-x"인지 확인
                        Debug.WriteLine($"[DEBUG-RAW] Addr: 0x{address.ToUInt64():X} => Prot: '{result.Protection}'");
                    }

                    return result;
                }
                catch { return null; }
            }

            public override UIntPtr FindExportByName(string moduleName, string exportName)
            {
                string addrStr = _fridaRpc.CallAsync<string>(
                    "findExportByName",
                    moduleName,
                    exportName
                ).GetAwaiter().GetResult();

                return ConvertToUIntPtr(addrStr);
            }

            public override List<string> EnumerateModules()
            {
                return _fridaRpc.CallAsync<List<string>>("enumerateModules")
                                .GetAwaiter().GetResult()!;
            }

            public override List<MemoryRange> EnumerateModuleRanges(string moduleName, bool includeData = false)
            {
                // [핵심] 모듈 이름이 null이거나 비어있으면 아예 JS를 호출하지 않고 빈 리스트 반환
                if (string.IsNullOrEmpty(moduleName))
                {
                    // LOG.Warning("EnumerateModuleRanges called with empty name.");
                    return new List<MemoryRange>();
                }

                try
                {
                    // 사용자님의 원래 코드대로 includeData를 포함하여 호출합니다.
                    // (단, script1.js에서 이 인자를 받지 않는다면 JS에서는 무시됩니다)
                    var ranges = _fridaRpc.CallAsync<List<MemoryRange>>(
                        "enumerateModuleRanges",
                        moduleName,
                        includeData
                    ).GetAwaiter().GetResult();

                    // 결과가 null이면 빈 리스트 반환 (캐싱 변수에 빈 리스트라도 저장되게 함)
                    return ranges ?? new List<MemoryRange>();
                }
                catch (Exception ex)
                {
                    // 에러 발생(통신 오류 등) 시에도 빈 리스트를 반환하여
                    // 호출부(MainModuleRanges)에서 무한 루프가 도는 것을 막습니다.
                    LOG.Error($"EnumerateModuleRanges Failed: {ex.Message}");
                    return new List<MemoryRange>();
                }
            }

            public override Dictionary<UIntPtr, Dictionary<string, object>> EnumerateExportedFunctions(bool updateCache = false)
            {
                // JSON 키는 항상 문자열이므로, <string, ...> 형태로 먼저 받습니다.
                //var rawResult = _fridaRpc.CallAsync<Dictionary<string, Dictionary<string, object>>>(
                //    "enumerateExportedFunctions",
                //    updateCache
                //).GetAwaiter().GetResult()!;

                // [수정] Dictionary가 아니라 List<FridaExportItem>으로 받습니다.
                var rawList = _fridaRpc.CallAsync<List<FridaExportItem>>(
                    "enumerateExportedFunctions",
                    updateCache
                ).GetAwaiter().GetResult();

                if (rawList == null)
                {
                    return new Dictionary<UIntPtr, Dictionary<string, object>>();
                }

                // [변환] List -> Dictionary<UIntPtr, Dictionary<string, object>>
                var result = new Dictionary<UIntPtr, Dictionary<string, object>>();

                foreach (var item in rawList)
                {
                    try
                    {
                        // 주소 문자열("0x...")을 숫자로 변환
                        string addrStr = item.Address;
                        if (string.IsNullOrEmpty(addrStr)) continue;

                        // 0x 접두사 제거 로직 (Frida는 보통 0x를 붙여줌)
                        ulong addressVal = Convert.ToUInt64(addrStr, 16);
                        UIntPtr ptr = (UIntPtr)addressVal;

                        // 내부 딕셔너리 구성
                        var infoDict = new Dictionary<string, object>
                        {
                            { "name", item.Name },
                            { "type", item.Type },
                            { "address", addressVal } // 편의상 숫자 주소도 저장
                        };

                        // 결과 딕셔너리에 추가 (중복 주소 방지)
                        if (!result.ContainsKey(ptr))
                        {
                            result.Add(ptr, infoDict);
                        }
                    }
                    catch (Exception ex)
                    {
                        // 변환 실패 시 로그만 남기고 계속 진행
                        LOG.Warning($"Failed to parse export item: {item.Name} ({item.Address}) - {ex.Message}");
                        continue;
                    }
                }

                return result;

                // string 키("0x1234")를 UIntPtr로 변환하여 반환
                //var result = new Dictionary<UIntPtr, Dictionary<string, object>>();
                //foreach (var kvp in rawResult)
                //{
                //    result[ConvertToUIntPtr(kvp.Key)] = kvp.Value;
                //}
                //return result;
            }

            public override UIntPtr AllocateProcessMemory(UIntPtr size, UIntPtr near)
            {
                string addrStr = _fridaRpc.CallAsync<string>(
                    "allocateProcessMemory",
                    size, // 크기는 숫자로
                    near  // 주소 힌트는 문자열로
                ).GetAwaiter().GetResult();

                return ConvertToUIntPtr(addrStr);
            }

            public override string QueryMemoryProtection(UIntPtr address)
            {
                return _fridaRpc.CallAsync<string>(
                    "queryMemoryProtection",
                    address
                ).GetAwaiter().GetResult()!;
            }

            public override bool SetMemoryProtection(UIntPtr address, UIntPtr size, string protection)
            {
                return _fridaRpc.CallAsync<bool>(
                    "setMemoryProtection",
                    address,
                    size,
                    protection
                ).GetAwaiter().GetResult();
            }

            public override byte[] ReadProcessMemory(UIntPtr address, UIntPtr size)
            {
                ulong totalSize = size.ToUInt64();
                ulong startAddress = address.ToUInt64();
                byte[] readData = new byte[totalSize];

                for (ulong offset = 0; offset < totalSize; offset += (ulong)MAX_DATA_CHUNK_SIZE)
                {
                    ulong chunkSize = Math.Min((ulong)MAX_DATA_CHUNK_SIZE, totalSize - offset);
                    UIntPtr currentAddr = (UIntPtr)(startAddress + offset);

                    // [핵심 수정] byte[] 대신 List<byte>로 받습니다. 
                    // (JsonException 해결: 숫자 배열 [1,2,3]을 받을 수 있음)
                    List<byte>? chunkList = null;

                    try
                    {
                        chunkList = _fridaRpc.CallAsync<List<byte>>(
                            "readProcessMemory",
                            currentAddr,
                            chunkSize
                        ).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        // 로그 필요시 추가
                    }

                    // List를 배열로 변환하여 사용
                    byte[] chunk = chunkList?.ToArray() ?? Array.Empty<byte>();

                    if (chunk.Length > 0)
                    {
                        int copyLength = Math.Min(chunk.Length, (int)chunkSize);
                        Buffer.BlockCopy(chunk, 0, readData, (int)offset, copyLength);
                    }
                }
                return readData;
            }

            public override void WriteProcessMemory(UIntPtr address, byte[] data)
            {
                // System.Text.Json은 byte[]를 Base64로 자동 직렬화합니다.
                // JS 측에서 이를 받으려면 hexdump나 base64 decode가 필요할 수 있으나,
                // 일반적인 Frida 바인딩은 이를 처리합니다.
                _fridaRpc.CallAsync<object>(
                    "writeProcessMemory",
                    address,
                    data
                ).GetAwaiter().GetResult();
            }

            public override void TerminateProcess()
            {
                try
                {
                    // RPC 호출로 덤프 종료 알림
                    _fridaRpc.CallAsync<object>("notifyDumpingFinished").GetAwaiter().GetResult();
                }
                catch { /* Ignore */ }
                finally
                {
                    // Dispose를 호출하여 내부적으로 세션을 정리하고 연결을 끊습니다.
                    _fridaSession.Dispose();
                }
            }

            private UIntPtr ConvertToUIntPtr(string hexStr)
            {
                try
                {
                    return (UIntPtr)Convert.ToUInt64(hexStr, 16);
                }
                catch
                {
                    return UIntPtr.Zero;
                }
            }

            public bool IsAddressInMainModule(UIntPtr address)
            {
                // MainModuleRanges 리스트가 비어있으면 false
                if (MainModuleRanges == null) return false;

                ulong targetAddr = address.ToUInt64();

                foreach (var range in MainModuleRanges)
                {
                    // MemoryRange의 Base와 Size는 ulong이라고 가정합니다.
                    // 만약 UIntPtr라면 range.Base.ToUInt64()로 변환하세요.
                    ulong start = range.Base;
                    ulong end = start + range.Size;

                    if (targetAddr >= start && targetAddr < end)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        // _str_to_architecture 대응
        public static Architecture StrToArchitecture(string fridaArch)
        {
            if (fridaArch == "ia32") return Architecture.X86_32; //
            if (fridaArch == "x64") return Architecture.X86_64; //
            throw new NotSupportedException($"Unsupported arch: {fridaArch}");
        }

        // spawn_and_instrument 대응
        public static FridaProcessControll SpawnAndInstrument(
            string pePath,
            List<MemoryRange> textSectionRanges,
            OepReachedCallback notifyOepReached) // 델리게이트를 인자로 받음
        {
            // DeviceManager 생성
            using var deviceManager = new FridaDeviceManager();

            // 2. 장치 목록을 가져와서 로컬 장치(Type == Local)를 찾습니다.
            var device = deviceManager.EnumerateDevices().FirstOrDefault(d => d.Type == DeviceType.Local)
                ?? throw new Exception("Local device not found.");
            uint pid;
            string fileName = Path.GetFileName(pePath);

            // 3. 어셈블리 정의(5개 인자)에 맞춰 Spawn 호출
            SpawnOptions options = new();

            if (Path.GetExtension(pePath).ToLower() == ".dll")
            {
                string rundll32 = @"C:\Windows\System32\rundll32.exe";
                string[] argv = [rundll32, pePath, "#0"];
                options.Argv = argv;
                pid = device.Spawn(rundll32,options);
            }
            else
            {
                string[] argv = [pePath];
                options.Argv = argv;
                pid = device.Spawn(pePath, options);
            }

            // 4. 세션 및 스크립트 생성
            var session = device.Attach(pid);

            // JS 리소스 로드
            string fridaJs = File.ReadAllText("Resources/frida.js");
            var script = session.CreateScript(fridaJs);

            // 스크립트 메시지 이벤트에 FridaCallback을 연결합니다.
            script.OnMessage += (sender, e) => FridaCallback(notifyOepReached, e.Json);
            script.Load();

            // 1. [핵심] RpcClient 생성 (이전 대화의 RpcClient 클래스 사용)
            var rpcClient = new ScriptRpcClient(script);

            // 2. 초기화 RPC 호출 ("setup_oep_tracing")
            var args = new object[]
            {
                Path.GetFileName(pePath),
                textSectionRanges.Select(r => new object[] {
                    r.Base,              // 주소는 SanitizeObject가 "0x..." 문자열로 바꿔도 JS가 알아먹음
                    r.Size.ToUInt64()    // ★ 핵심: 크기는 '숫자'로 가야하므로 포인터 형식을 벗겨냄
                }).ToArray()
            };
            rpcClient.CallAsync<object>("setupOepTracing", args).GetAwaiter().GetResult();

            // 3. [핵심] 생성자에 넘겨줄 환경 정보 조회 (RPC 호출)
            // 파이썬의 self.script.exports.get_arch() 등에 해당
            string archStr = rpcClient.CallAsync<string>("getArchitecture").GetAwaiter().GetResult();
            int pointerSize = rpcClient.CallAsync<int>("getPointerSize").GetAwaiter().GetResult();
            int pageSize = rpcClient.CallAsync<int>("getPageSize").GetAwaiter().GetResult();

            // 4. 프로세스 재개
            device.Resume(pid);

            // 5. [수정] 준비된 값으로 컨트롤러 생성
            return new FridaProcessControll(
                (int)pid,
                Path.GetFileName(pePath),
                session,
                script,
                rpcClient, // RpcClient 전달
                StrToArchitecture(archStr), // 미리 변환해서 전달
                pointerSize,
                pageSize
            );
        }

        // _frida_callback 대응
        private static void FridaCallback(OepReachedCallback notifyOepReached, string message)
        {
            try
            {
                using var json = JsonDocument.Parse(message);
                var root = json.RootElement;

                // 1. 안전하게 'type' 속성 확인
                if (root.TryGetProperty("type", out var typeProp) && typeProp.GetString() == "send")
                {
                    // 2. 'payload'가 존재하고 객체인지 확인
                    if (root.TryGetProperty("payload", out var payload) && payload.ValueKind == JsonValueKind.Object)
                    {
                        // 3. 'event'가 'oep_reached'인지 확인
                        if (payload.TryGetProperty("event", out var eventProp) && eventProp.GetString() == "oep_reached")
                        {
                            // 4. [중요] 16진수 문자열 파싱 (0x 제거)
                            string baseHex = payload.GetProperty("BASE").GetString() ?? "0";
                            string oepHex = payload.GetProperty("OEP").GetString() ?? "0";

                            // "0x" 혹은 "0X"가 있다면 제거
                            if (baseHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                baseHex = baseHex.Substring(2);
                            if (oepHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                oepHex = oepHex.Substring(2);

                            long baseAddr = Convert.ToInt64(baseHex, 16);
                            long oepAddr = Convert.ToInt64(oepHex, 16);
                            bool isDotNet = payload.GetProperty("DOTNET").GetBoolean();

                            // 5. 델리게이트 호출
                            notifyOepReached(baseAddr, oepAddr, isDotNet);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // JSON 파싱 에러나 변환 에러가 발생해도 프로그램이 죽지 않도록 방어
                Console.WriteLine($"[FridaCallback Error] {ex.Message}");
            }
        }
    }

    // JSON 데이터 수신용 DTO (Data Transfer Object)
    public class FridaExportItem
    {
        [System.Text.Json.Serialization.JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("address")]
        public string Address { get; set; } = string.Empty; // "0xe06b0c" 같은 문자열로 옴
    }

}
