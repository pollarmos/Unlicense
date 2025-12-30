using Frida.Events;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace TESTRPC;

public class FridaMessageHandler
{
    // [상태 플래그] 메인 함수가 이 변수들을 감시합니다.
    public bool IsOepFound { get; private set; } = false;
    public bool IsIatFinished { get; private set; } = false;

    // [데이터 저장소]
    public string OepAddress { get; private set; }
    public List<string> CollectedExports { get; private set; } = new List<string>();

    public void OnMessage(object sender, ScriptMessageEventArgs e)
    {
        try
        {
            var node = JsonNode.Parse(e.Json);

            // 1. RPC 응답(배열) 무시 - 여기서는 관심 없음
            if (node is JsonArray) return;

            var type = node?["type"]?.ToString();

            if (type == "send")
            {
                var payload = node?["payload"];

                // (A) payload가 배열이면 -> IAT 데이터 청크
                if (payload is JsonArray arr)
                {
                    // RPC 포장지(["frida:rpc", ID, "ok", [데이터]]) 구조일 경우
                    if (arr.Count >= 4 && arr[3] is JsonArray dataArr)
                    {
                        Console.WriteLine($"[Data] IAT 청크 수신: {dataArr.Count} 개");
                        foreach (var item in dataArr)
                        {
                            // 필요한 데이터만 간단히 저장 (예: "이름 : 주소")
                            CollectedExports.Add($"{item["name"]} : {item["address"]}");
                        }
                    }
                    return;
                }

                // (B) payload가 객체이면 -> 이벤트 (OEP 발견, 완료 등)
                var eventName = payload?["event"]?.ToString();

                if (eventName == "oep_reached")
                {
                    OepAddress = payload?["OEP"]?.ToString();
                    Console.WriteLine($"[Event] OEP 발견됨! 주소: {OepAddress}");
                    IsOepFound = true; // ★ 플래그 ON
                }
                else if (eventName == "export_finished")
                {
                    Console.WriteLine($"[Event] 모든 IAT 수집 완료.");
                    IsIatFinished = true; // ★ 플래그 ON
                }
            }
            else if (type == "log")
            {
                Console.WriteLine($"[JS Log] {node?["payload"]}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Handler Error] {ex.Message}");
        }
    }
}
