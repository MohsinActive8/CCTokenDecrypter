using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Utility
{
    public enum Logger_level
    {
        info,
        success,
        warning,
        error
    }
    public static class Logger
    {
        public static void Log(string message)
        {
            WriteToFile(message, Logger_level.info);
        }

        public static void Error(string message)
        {
            WriteToFile(message, Logger_level.error);
        }

        private static void WriteToFile(string message, Logger_level level)
        {
            if (!Directory.Exists(Path.Combine(AppContext.BaseDirectory, $"Logs")))
                Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, $"Logs"));

            using (var str = File.AppendText(Path.Combine(AppContext.BaseDirectory, $"Logs\\{DateTime.Now.ToString("MM-dd-yyyy")}.txt")))
            {
                str.WriteLine("Log Level: " + level.ToString().ToUpper() + " [" + DateTime.UtcNow + "]" + " :: " + message);
            }
        }
    }
}
