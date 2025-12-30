using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    public class VersionDetection
    {
        public static readonly string[] Themida2ImportedMods = { "kernel32.dll", "comctl32.dll" };

        public static readonly ReadOnlyCollection<string> Themida2ImportedFuncs = new(["lstrcpy", "InitCommonControls"]);

        private static readonly byte[][] InstrPatterns = [
                [0x56, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58],
                [0x83, 0xEC, 0x04, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58]
            ];

        private static readonly Logger LOG = new("WinLicenseDetector");

        public static int? DetectWinlicenseVersion(string peFilePath)
        {
            PEFile binary;
            try
            {
                binary = PEFile.FromFile(peFilePath);
                
            }
            catch 
            {
                LOG.Error($"Failed to parse PE '{peFilePath}'");
                return null; 
            }

            // -----------------------------------------------------------
            // Version 3.x 체크 로직
            // -----------------------------------------------------------
            // .themida 또는 .winlice 섹션이 있는지 확인합니다.
            if (binary.Sections.Any(s => s.Name == ".themida" || s.Name == ".winlice"))
            {
                return 3; // 버전 3으로 판단
            }

            // Version 2.x 체크 로직
            // 임포트 모듈과 함수 목록을 추출합니다.
            IPEImage image = PEImage.FromFile(peFilePath);
            if (image.Imports.Count == 2)
            {
                int totalFunctions = image.Imports.Sum(m => m.Symbols.Count);
                if (totalFunctions == 2)
                {
                    var currentMods = image.Imports.Select(m => m.Name?.ToLower() ?? "").ToList();
                    // 모듈 2개 체크 확인
                    bool modsMatch = currentMods.All(n => Themida2ImportedMods.Contains(n));
                    if (modsMatch)
                    {
                        // 함수(Symbol) 이름 추출 및 검사
                        // 2개 모듈의 모든 심볼 이름을 리스트로 만듭니다.
                        var currentFuncs = image.Imports
                            .SelectMany(m => m.Symbols)
                            .Select(s => s.Name ?? "")
                            .ToList();

                        // 정의된 함수 리스트와 비교
                        bool funcsMatch = currentFuncs.All(f => Themida2ImportedFuncs.Contains(f));

                        if (funcsMatch)
                        {
                            return 2; // 모듈과 함수가 모두 일치할 때만 버전 2로 확정
                        }
                    }
                }
            }

            // These x86 instructions are always present at the beginning of a section
            // in Themida/WinLicense 2.x
            foreach (var section in binary.Sections)
            {
                if (section.Contents is IReadableSegment readable)
                {
                    var reader = readable.CreateReader();
                    int bytesToRead = Math.Min((int)reader.Length, 12);
                    byte[] buffer = new byte[bytesToRead];
                    reader.ReadBytes(buffer);

                    foreach (var pattern in InstrPatterns)
                    {
                        if (buffer.Length >= pattern.Length &&
                            buffer.AsSpan(0, pattern.Length).SequenceEqual(pattern))
                        {
                            return 2;
                        }
                    }
                }
            }
            return null;
        }
    }
}
