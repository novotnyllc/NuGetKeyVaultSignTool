using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using LogLevel = NuGet.Common.LogLevel;

namespace NuGetKeyVaultSignTool
{
	class NuGetLogger : NuGet.Common.ILogger
	{
        readonly ILogger logger;

        public NuGetLogger(ILogger logger)
	    {
            this.logger = logger;
        }

        public void Log(NuGet.Common.LogLevel level, string data)
        {
            logger.Log(ConvertLevel(level), data);
        }

        public void Log(ILogMessage message)
        {
            Log(message.Level, message.FormatWithCode());
        }

        public Task LogAsync(NuGet.Common.LogLevel level, string data)
        {
            Log(level, data);
            return Task.CompletedTask;
        }

        public Task LogAsync(ILogMessage message)
        {
            Log(message.Level, message.FormatWithCode());

            return Task.CompletedTask;
        }

        public void LogDebug(string data)
        {
            Log(LogLevel.Debug, data);
        }

        public void LogError(string data)
        {
            Log(LogLevel.Error, data);
        }

        public void LogInformation(string data)
        {
            Log(LogLevel.Information, data);
        }

        public void LogInformationSummary(string data)
        {
            Log(LogLevel.Information, data);
        }

        public void LogMinimal(string data)
        {
            Log(LogLevel.Minimal, data);
        }

        public void LogVerbose(string data)
        {
            Log(LogLevel.Verbose, data);
        }

        public void LogWarning(string data)
        {
            Log(LogLevel.Warning, data);
        }

	    static Microsoft.Extensions.Logging.LogLevel ConvertLevel(LogLevel level)
	    {
            switch (level)
            {
                case LogLevel.Debug:
                    return Microsoft.Extensions.Logging.LogLevel.Debug;
                case LogLevel.Verbose:
                    return Microsoft.Extensions.Logging.LogLevel.Trace;
                case LogLevel.Information:
                    return Microsoft.Extensions.Logging.LogLevel.Information;
                case LogLevel.Minimal:
                    return Microsoft.Extensions.Logging.LogLevel.Information;
                case LogLevel.Warning:
                    return Microsoft.Extensions.Logging.LogLevel.Warning;
                case LogLevel.Error:
                    return Microsoft.Extensions.Logging.LogLevel.Error;

                default:
                    return Microsoft.Extensions.Logging.LogLevel.Information;
            }
        }


    }
}