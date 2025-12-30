using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Unlicense.Core
{
    public enum LogLevel
    {
        DEBUG = 10,
        INFO = 20,
        WARNING = 30,
        ERROR = 40,
        CRITICAL = 50
    }

    public class Logger
    {
        private readonly string _name;
        public LogLevel Level { get; set; } = LogLevel.INFO;

        public Logger(string name)
        {
            _name = name;
        }

        public void Debug(string message) => Log(LogLevel.DEBUG, message);
        public void Info(string message) => Log(LogLevel.INFO, message);
        public void Warning(string message) => Log(LogLevel.WARNING, message);
        public void Error(string message) => Log(LogLevel.ERROR, message);
        public void Critical(string message) => Log(LogLevel.CRITICAL, message);

        private void Log(LogLevel level, string message)
        {
            if (level < this.Level) return;

            // CustomFormatter.format() 로직 구현
            var originalColor = Console.ForegroundColor;
            string prefix = level.ToString();

            switch (level)
            {
                case LogLevel.DEBUG:
                    Console.ForegroundColor = ConsoleColor.Gray; // grey
                    break;
                case LogLevel.INFO:
                    Console.ForegroundColor = ConsoleColor.Green; // green
                    break;
                case LogLevel.WARNING:
                    Console.ForegroundColor = ConsoleColor.Yellow; // yellow
                    break;
                case LogLevel.ERROR:
                    Console.ForegroundColor = ConsoleColor.Red; // red
                    break;
                case LogLevel.CRITICAL:
                    Console.ForegroundColor = ConsoleColor.DarkRed; // bold_red
                    break;
            }

            // "[LEVEL] - MESSAGE" 형식 출력
            Console.Write(prefix);
            Console.ForegroundColor = originalColor; // 메시지는 기본 색상으로 (reset 효과)
            Console.WriteLine($" - {message}");
        }

    }

    public class LogManager
    {
        public static void SetupLogger(Logger logger, bool verbose)
        {
            logger.Level = verbose ? LogLevel.DEBUG : LogLevel.INFO;
        }
    }

}
