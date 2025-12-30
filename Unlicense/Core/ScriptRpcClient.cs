using Frida;
using Frida.Events;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;


namespace Unlicense.Core
{
    public class ScriptRpcClient : IDisposable
    {
        private readonly FridaScript _script;
        private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _pendingRequests;
        private long _nextRequestId = 1;

        // 중복 호출 방지를 위한 플래그
        private bool _disposed;

        public ScriptRpcClient(FridaScript script)
        {
            _script = script;
            _pendingRequests = new ConcurrentDictionary<string, TaskCompletionSource<JsonElement>>();

            // OnMessage 이벤트 구독
            _script.OnMessage += OnScriptMessage;
        }

        public async Task<T> CallAsync<T>(string methodName, params object[] args)
        {
            // 이미 Dispose된 경우 호출 차단
            ObjectDisposedException.ThrowIf(_disposed, this);
            object[] sanitizedArgs = SanitizeArgs(args);

            string requestId = (_nextRequestId++).ToString();
            var tcs = new TaskCompletionSource<JsonElement>();
            _pendingRequests.TryAdd(requestId, tcs);

            try
            {
                var payload = new object[]
                {
                    "frida:rpc",
                    requestId,
                    "call",
                    methodName,
                    sanitizedArgs
                };

                string jsonString = JsonSerializer.Serialize(payload);

                // Post 메소드 사용
                _script.Post(jsonString);

                JsonElement resultElement = await tcs.Task;
                return resultElement.Deserialize<T>()!;
            }
            finally
            {
                _pendingRequests.TryRemove(requestId, out _);
            }
        }

        private void OnScriptMessage(object? sender, ScriptMessageEventArgs e)
        {
            // [디버깅] 들어오는 모든 메시지 확인 (필요시 주석 해제)
            // System.Diagnostics.Debug.WriteLine($"[Script Message] {e.Json}");

            if (_disposed) return;

            try
            {
                using (JsonDocument doc = JsonDocument.Parse(e.Json))
                {
                    JsonElement root = doc.RootElement;
                    JsonElement rpcMessage = root;

                    // 1. 메시지가 {"type":"send", "payload":[...]} 형태인지 확인하고 payload 꺼내기
                    if (root.ValueKind == JsonValueKind.Object &&
                        root.TryGetProperty("payload", out var payloadProp))
                    {
                        rpcMessage = payloadProp;
                    }

                    // 2. ["frida:rpc", requestId, status, result] 배열인지 확인
                    if (rpcMessage.ValueKind == JsonValueKind.Array &&
                        rpcMessage.GetArrayLength() >= 4 &&
                        rpcMessage[0].GetString() == "frida:rpc")
                    {
                        string requestId = rpcMessage[1].GetString()!;
                        string status = rpcMessage[2].GetString()!; // "ok" or "error"

                        if (_pendingRequests.TryGetValue(requestId, out var tcs))
                        {
                            if (status == "ok")
                            {
                                // ★ [핵심 수정] .Clone()을 사용하여 메모리 복사본을 생성합니다.
                                // 이렇게 하면 using(doc)가 끝나도 데이터가 살아있습니다.
                                tcs.TrySetResult(rpcMessage[3].Clone());
                            }
                            else
                            {
                                // 에러 메시지는 단순 문자열로 변환해서 넘김
                                tcs.TrySetException(new Exception(rpcMessage[3].ToString()));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RPC Error] {ex.Message}");
            }
        }

        // [재귀 함수] 객체 내부를 깊숙이 탐색하여 UIntPtr/IntPtr을 찾아 문자열로 바꿉니다.
        [return: NotNullIfNotNull(nameof(arg))]
        private static object? SanitizeObject(object arg)
        {
            if (arg == null) return null;

            // 1. 포인터 타입 발견 시 Hex 문자열로 변환 (핵심)
            if (arg is UIntPtr uPtr)
                return "0x" + uPtr.ToUInt64().ToString("x");
            if (arg is IntPtr iPtr)
                return "0x" + iPtr.ToInt64().ToString("x");

            // 2. 문자열이나 바이트 배열은 내부에 포인터가 없으므로 그대로 반환
            // (byte[]를 재귀로 돌리면 [1, 2...] 형태가 되는데, 보통 Base64 처리가 효율적이므로 제외)
            if (arg is string || arg is byte[])
                return arg;

            // 3. 배열, 리스트 등 컬렉션인 경우 -> 내부 요소를 하나하나 재귀 호출
            if (arg is System.Collections.IEnumerable enumerable)
            {
                var list = new System.Collections.Generic.List<object>();
                foreach (var item in enumerable)
                {
                    // 자기 자신을 다시 호출하여 내부 깊숙한 곳까지 검사
                    list.Add(SanitizeObject(item));
                }
                return list.ToArray();
            }

            // 4. 그 외 기본 타입(int, bool 등)은 그대로 통과
            return arg;
        }

        // [메인 헬퍼] 외부에서 호출하는 진입점
        private static object[] SanitizeArgs(object[] args)
        {
            if (args == null) return Array.Empty<object>();

            // 전체 args 배열을 재귀 함수에 넣어서 처리
            return (object[])SanitizeObject(args);
        }


        public void Dispose()
        {
            Dispose(true);
            // GC에게 "이 객체는 이미 정리했으니 종료자(Finalizer)를 호출하지 마라"고 알림
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // 관리되는 리소스(Managed Resources) 정리
                    _script.OnMessage -= OnScriptMessage;

                    foreach (var tcs in _pendingRequests.Values)
                    {
                        tcs.TrySetCanceled();
                    }
                    _pendingRequests.Clear();
                }

                // (여기에 비관리 리소스 해제 코드가 있다면 작성)

                _disposed = true;
            }
        }
    }

   
}
