using AsmResolver.PE.File;
using Frida;
using Frida.Data;
using Frida.Events;
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;


class Program
{
    // 테스트할 32비트 실행 파일 경로
    private const string TargetExePath = @"d:\ragnarok\ragexe.exe";
    private const string ScriptPath = "frida.js";

    static void Main(string[] args)
    {
        ForceRunAsInvoker();

        var binary = PEFile.FromFile(TargetExePath);
        var sections = binary.Sections;
        var imageBase = binary.OptionalHeader.ImageBase;
        var textRva = sections[0].Rva;
        var textSize = sections[0].GetVirtualSize();

        using var deviceManager = new FridaDeviceManager();

        var localDevice = deviceManager.EnumerateDevices().FirstOrDefault(d => d.Type == DeviceType.Local);
        if (localDevice == null) return;
        
        try
        {
            uint pid = localDevice.Spawn(TargetExePath);  
            using var session = localDevice.Attach(pid);
            string scriptSource = File.ReadAllText(ScriptPath);
            using var script = session.CreateScript(scriptSource);

            script.OnMessage += (sender, e) => HandleScriptMessage(script, e);
            script.Load();

            string moduleName = Path.GetFileName(TargetExePath);

            var oepRanges = new object[] { new object[] { textRva, textSize } };
            CallRpcMethod(script, "setupOepTracing", moduleName, oepRanges);

            localDevice.Resume(pid);

            using var mainContext = GLib.MainContext.RefThreadDefault();

            while (true)
            {
                if (mainContext.Pending())
                {
                    mainContext.Iteration(false);
                }
                else
                {
                    // 이벤트가 없을 때만 살짝 대기
                    Thread.Sleep(10);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

    }

    // JS의 send() 메시지를 처리하는 핸들러
    private static void HandleScriptMessage(FridaScript script, ScriptMessageEventArgs e)
    {
        try
        {
            var jsonNode = JsonNode.Parse(e.Json);
            if (jsonNode is JsonArray) return;

            var type = jsonNode?["type"]?.ToString();
            if (type == "log")
            {
                var payload = jsonNode?["payload"]?.ToString();
                Console.WriteLine($"[JS Log] {payload}");
            }
            else if (type == "send")
            {
                var payload = jsonNode?["payload"];

                // ★★★ [수정 핵심] payload 자체가 "배열(JsonArray)"인지 확인 ★★★
                if (payload is JsonArray payloadArray)
                {
                    Console.WriteLine($"[C#] 대용량 배열 수신됨! 크기: {payloadArray.Count} 개");
                    //Console.WriteLine($"[Script Msg] {payload}");
                    // 여기서 payloadArray를 사용하면 됩니다.
                    // 예: 첫 번째 데이터 확인
                    if (payloadArray.Count > 0)
                    {
                        Console.WriteLine($"[Sample] {payloadArray[0]?.ToJsonString()}");
                    }

                    // 메모리 해제
                    payloadArray = null;
                    GC.Collect();
                    return; // 처리했으니 종료
                }

                // 배열이 아니면 기존 로직(이벤트 확인 등) 수행
                Console.WriteLine($"[Script Msg] {payload}"); // 내용이 너무 크면 주석 처리

                if (payload is JsonObject && payload["event"]?.ToString() == "oep_reached")
                {
                    var oep = payload["OEP"]?.ToString();
                    var baseAddr = payload["BASE"]?.ToString();
                    Console.WriteLine($"[+] OEP REACHED! Address: {oep}, Base: {baseAddr}");

                    string targetModuleName = "ragexe.exe"; // 타겟 실행 파일 이름
                                                            // RPC 패킷 수동 생성: ["frida:rpc", "ID", "call", "함수명", [인자]]
                    var rpcPacket = new object[]
                    {
                    "frida:rpc",
                    Guid.NewGuid().ToString(),
                    "call",
                    "enumerateExportedFunctions",
                    new object[] { targetModuleName }
                    };

                    // 전송 (Fire-and-Forget)
                    string rpcJson = JsonSerializer.Serialize(rpcPacket);
                    script.Post(rpcJson);

                    Console.WriteLine("[*] IAT 목록 추출 요청 전송 완료 (enumerateExportedFunctions)");

                    Thread.Sleep(200);

                    Console.WriteLine("[*] Sending 'block_on_oep' to resume script execution...");
                    var resumeMessage = JsonSerializer.Serialize(new { type = "block_on_oep" });
                    script.Post(resumeMessage);
                }
            }
            else if (type == "error")
            {
                Console.WriteLine($"[Script Error] {jsonNode?["description"]}");
                Console.WriteLine($"[Stack] {jsonNode?["stack"]}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Message parsing error: {ex.Message}");
        }
    }

    // Frida RPC 프로토콜에 맞춰 메서드를 호출하는 헬퍼
    private static void CallRpcMethod(FridaScript script, string methodName, params object[] args)
    {
        // Frida RPC 요청 규격: ["frida:rpc", "요청ID", "call", "함수명", [인자배열]]
        // 이 배열 자체가 메시지 본문(Payload)이어야 합니다.

        var requestId = Guid.NewGuid().ToString();

        var rpcPacket = new object[]
        {
            "frida:rpc",
            requestId,
            "call",
            methodName,
            args
        };

        // 껍데기 없이 배열 자체를 JSON으로 변환하여 전송
        string json = JsonSerializer.Serialize(rpcPacket);

        // 로그로 전송 내용 확인 (디버깅용)
        Console.WriteLine($"[*] Sending RPC: {json}");

        script.Post(json);
    }

    // 관리자 권한으로 실행
    private static void ForceRunAsInvoker()
    {
        Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RUNASINVOKER");
    }
}