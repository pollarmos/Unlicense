using AsmResolver.PE.File;
using Frida;
using Frida.Data;
using Frida.Events;
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using TESTRPC;


class Program
{
    // 테스트할 32비트 실행 파일 경로
    private const string TargetExePath = @"d:\ragnarok\ragexe.exe";
    private const string ScriptPath = "frida.js";

    static void Main(string[] args)
    {
        ForceRunAsInvoker(); // (기존 함수 유지)

        // 1. PE 정보 읽기 (기존 코드)
        var binary = PEFile.FromFile(TargetExePath);
        var sections = binary.Sections;
        var textRva = sections[0].Rva;
        var textSize = sections[0].GetVirtualSize();

        using var deviceManager = new FridaDeviceManager();
        var localDevice = deviceManager.EnumerateDevices().FirstOrDefault(d => d.Type == DeviceType.Local);
        if (localDevice == null) return;

        try
        {
            // 2. 프로세스 실행 및 스크립트 로드
            uint pid = localDevice.Spawn(TargetExePath);
            using var session = localDevice.Attach(pid);
            string scriptSource = File.ReadAllText(ScriptPath);
            using var script = session.CreateScript(scriptSource);

            // ★ [클래스 연결]
            var messageHandler = new FridaMessageHandler();
            var rpcClient = new RpcClient(script);

            // 핸들러 등록
            script.OnMessage += messageHandler.OnMessage;
            script.Load();

            // 3. Frida 컨텍스트 준비
            using var mainContext = GLib.MainContext.RefThreadDefault();

            // =============================================================
            // [STEP 1] OEP 찾기 실행
            // =============================================================
            Console.WriteLine("\n[Step 1] OEP 추적 시작...");

            string moduleName = Path.GetFileName(TargetExePath);
            var oepRanges = new object[] { new object[] { textRva, textSize } };

            // RPC 호출
            rpcClient.Call("setupOepTracing", moduleName, oepRanges);
            localDevice.Resume(pid);

            // ★ 대기 로직: OEP를 찾을 때까지 GLib 루프를 돌리며 대기
            while (!messageHandler.IsOepFound)
            {
                if (mainContext.Pending()) mainContext.Iteration(false);
                else Thread.Sleep(10);
            }
            Console.WriteLine("[Step 1] 완료. 다음 단계로 넘어갑니다.");

            // =============================================================
            // [STEP 2] IAT 추출 (OEP 찾은 후 실행)
            // =============================================================
            Console.WriteLine("\n[Step 2] IAT 추출 시작...");

            // RPC 호출 (명령만 내림)
            rpcClient.Call("enumerateExportedFunctions", moduleName);

            // JS 깨우기 (Wait 풀기)
            rpcClient.SendResumeSignal();

            // ★ 대기 로직: IAT 수집이 끝날 때까지 대기
            while (!messageHandler.IsIatFinished)
            {
                if (mainContext.Pending()) mainContext.Iteration(false);
                else Thread.Sleep(10);
            }

            // =============================================================
            // [결과 확인]
            // =============================================================
            Console.WriteLine("\n[Final] 모든 작업 종료.");
            Console.WriteLine($"수집된 함수 개수: {messageHandler.CollectedExports.Count}");

            // 결과 샘플 출력
            if (messageHandler.CollectedExports.Count > 0)
                Console.WriteLine($"Sample: {messageHandler.CollectedExports[0]}");

            Console.ReadLine(); // 종료 방지
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Error: {ex.Message}");
        }
    }
   
    // 관리자 권한으로 실행
    private static void ForceRunAsInvoker()
    {
        Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RUNASINVOKER");
    }
}