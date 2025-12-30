using Frida;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TESTRPC;

public class RpcClient
{
    private readonly FridaScript _script;

    public RpcClient(FridaScript script)
    {
        _script = script;
    }

    // JS 함수를 호출만 하고 결과는 기다리지 않음 (Fire-and-Forget)
    public void Call(string methodName, params object[] args)
    {
        var request = new object[]
        {
            "frida:rpc",
            Guid.NewGuid().ToString(),
            "call",
            methodName,
            args
        };

        string json = System.Text.Json.JsonSerializer.Serialize(request);
        _script.Post(json);
    }

    // JS의 wait() 상태를 풀어주는 단순 신호 전송
    public void SendResumeSignal()
    {
        string json = System.Text.Json.JsonSerializer.Serialize(new { type = "block_on_oep" });
        _script.Post(json);
    }
}
