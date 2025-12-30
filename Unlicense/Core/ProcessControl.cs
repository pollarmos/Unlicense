using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;


namespace Unlicense.Core
{
    // 1. Architecture Enumeration
    public enum Architecture
    {
        X86_32 = 0,
        X86_64 = 1
    }

    public class FridaUIntPtrConverter : JsonConverter<UIntPtr>
    {
        public override UIntPtr Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            // 1. 숫자로 들어오는 경우 (예: 12345)
            if (reader.TokenType == JsonTokenType.Number)
            {
                if (reader.TryGetUInt64(out ulong value))
                {
                    return (UIntPtr)value;
                }
            }
            // 2. 문자열로 들어오는 경우 (예: "0x401000" 또는 "401000")
            else if (reader.TokenType == JsonTokenType.String)
            {
                string? hexString = reader.GetString();
                if (string.IsNullOrEmpty(hexString)) return UIntPtr.Zero;

                // "0x" 접두사 제거
                if (hexString.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    hexString = hexString.Substring(2);
                }

                try
                {
                    // 16진수 문자열 -> ulong -> UIntPtr 변환
                    ulong value = Convert.ToUInt64(hexString, 16);
                    return (UIntPtr)value;
                }
                catch
                {
                    return UIntPtr.Zero;
                }
            }

            return UIntPtr.Zero;
        }

        public override void Write(Utf8JsonWriter writer, UIntPtr value, JsonSerializerOptions options)
        {
            // 다시 JSON으로 쓸 때는 숫자로 내보냄
            writer.WriteNumberValue(value.ToUInt64());
        }
    }

    // 2. MemoryRange Class
    public class MemoryRange
    {
        // 파이썬의 각 필드와 1:1 대응
        [JsonPropertyName("base")]
        [JsonConverter(typeof(FridaUIntPtrConverter))] // (만약 "0x..." 문자열 변환 에러나면 필요하지만 일단 속성명부터)
        public UIntPtr Base { get; set; }

        [JsonPropertyName("size")]
        [JsonConverter(typeof(FridaUIntPtrConverter))]
        public UIntPtr Size { get; set; }

        [JsonPropertyName("protection")]
        public string Protection { get; set; }

        [JsonIgnore]
        public byte[]? Data { get; set; }

        public MemoryRange()
        {
            Protection = string.Empty; // 기본값
        }

        public MemoryRange(UIntPtr @base, UIntPtr size, string protection, byte[]? data = null)
        {
            Base = @base;
            Size = size;
            Protection = protection;
            Data = data;
        }

        // 파이썬의 __str__ 대응 (ToString 오버라이드)
        public override string ToString()
        {
            return $"(base=0x{Base:x}, size=0x{Size:x}, prot={Protection})";
        }

        // 특정 주소가 범위 내에 있는지 확인 (addr: int 대응)
        public bool Contains(UIntPtr addr)
        {
            // .NET 8.0: UIntPtr 간의 비교 및 산술 연산 (+, <, >=) 지원
            // base <= addr < (base + size)
            return addr >= Base && addr < (Base + Size);
        }

        // [추가 권장] ulong 타입의 RVA/주소를 바로 비교하기 위한 오버로딩
        public bool Contains(ulong addr)
        {
            // 내부적으로 64비트 정수로 변환하여 비교 (가장 안전함)
            ulong baseVal = Base.ToUInt64();
            ulong sizeVal = Size.ToUInt64();
            return addr >= baseVal && addr < (baseVal + sizeVal);
        }
    }

    // 추상 클래스
    public abstract class ProcessControl
    {
        // 1. 공통 속성 (Properties)
        public int Pid { get; }
        public string MainModuleName { get; }
        public Architecture Architecture { get; }
        public int PointerSize { get; }
        public int PageSize { get; }

        // 2. 내부 캐시 필드 (Python's self._main_module_ranges)
        protected List<MemoryRange>? _mainModuleRanges = null;

        // 3. 생성자 (Python's __init__)
        protected ProcessControl(int pid, string mainModuleName, Architecture architecture, int pointerSize, int pageSize)
        {
            Pid = pid;
            MainModuleName = mainModuleName;
            Architecture = architecture;
            PointerSize = pointerSize;
            PageSize = pageSize;
        }

        // 4. 추상 메서드들 (자식 클래스에서 반드시 구현해야 함)
        public abstract Dictionary<string, object>? FindModuleByAddress(UIntPtr address);
        public abstract MemoryRange? FindRangeByAddress(UIntPtr address, bool includeData = false);
        public abstract UIntPtr FindExportByName(string moduleName, string exportName);
        public abstract List<string> EnumerateModules();
        public abstract List<MemoryRange> EnumerateModuleRanges(string moduleName, bool includeData = false);
        public abstract Dictionary<UIntPtr,Dictionary<string, object>> EnumerateExportedFunctions(bool updateCache = false);
        public abstract UIntPtr AllocateProcessMemory(UIntPtr size, UIntPtr near);
        public abstract string QueryMemoryProtection(UIntPtr address);
        public abstract bool SetMemoryProtection(UIntPtr address, UIntPtr size, string protection);
        public abstract byte[] ReadProcessMemory(UIntPtr address, UIntPtr size);
        public abstract void WriteProcessMemory(UIntPtr address, byte[] data );
        public abstract void TerminateProcess();

        // 캐시 로직
        public List<MemoryRange> MainModuleRanges => _mainModuleRanges ??= EnumerateModuleRanges(MainModuleName, true);

        // 캐시 삭제
        public void ClearCachedData() => _mainModuleRanges = null;

    }

    // 1. 모든 프로세스 컨트롤러 관련 예외의 조상 (ProcessControllerException)
    public class ProcessControllerException : Exception
    {
        public ProcessControllerException() : base() { }
        public ProcessControllerException(string message) : base(message) { }
        public ProcessControllerException(string message, Exception innerException)
            : base(message, innerException) { }
    }

    // 2. 메모리 조회(Query) 관련 오류
    public class QueryProcessMemoryError : ProcessControllerException
    {
        public QueryProcessMemoryError() : base() { }
        public QueryProcessMemoryError(string message) : base(message) { }
        public QueryProcessMemoryError(string message, Exception innerException)
            : base(message, innerException) { }
    }

    // 3. 메모리 읽기(Read) 관련 오류
    public class ReadProcessMemoryError : ProcessControllerException
    {
        public ReadProcessMemoryError() : base() { }
        public ReadProcessMemoryError(string message) : base(message) { }
        public ReadProcessMemoryError(string message, Exception innerException)
            : base(message, innerException) { }
    }

    // 4. 메모리 쓰기(Write) 관련 오류
    public class WriteProcessMemoryError : ProcessControllerException
    {
        public WriteProcessMemoryError() : base() { }
        public WriteProcessMemoryError(string message) : base(message) { }
        public WriteProcessMemoryError(string message, Exception innerException)
            : base(message, innerException) { }
    }

}
