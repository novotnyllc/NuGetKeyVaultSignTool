using Microsoft.Extensions.Logging;
using NuGet.Common;
using System.Threading.Tasks;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using LogLevel = NuGet.Common.LogLevel;

namespace NuGetKeyVaultSignTool;

internal class NuGetLogger(ILogger logger, string fileName) : NuGet.Common.ILogger
{
    public void Log(NuGet.Common.LogLevel level, string data)
    {
        logger.Log(ConvertLevel(level), "NuGet [{fileName}]: {data}", fileName, data);
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

    private static Microsoft.Extensions.Logging.LogLevel ConvertLevel(LogLevel level)
    {
        return level switch
        {
            LogLevel.Debug => Microsoft.Extensions.Logging.LogLevel.Debug,
            LogLevel.Verbose => Microsoft.Extensions.Logging.LogLevel.Trace,
            LogLevel.Information => Microsoft.Extensions.Logging.LogLevel.Information,
            LogLevel.Minimal => Microsoft.Extensions.Logging.LogLevel.Information,
            LogLevel.Warning => Microsoft.Extensions.Logging.LogLevel.Warning,
            LogLevel.Error => Microsoft.Extensions.Logging.LogLevel.Error,

            _ => Microsoft.Extensions.Logging.LogLevel.Information,
        };
    }
}