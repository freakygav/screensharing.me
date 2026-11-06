using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Screensharing.Scanner.Instance;

/// <summary>What could be read about one running Java process. Nothing here is persisted except what the resolver selects.</summary>
public sealed record JavaProcessInfo
{
    public required int Pid { get; init; }
    public int ParentPid { get; init; }
    public required string Name { get; init; }
    public string? ExecutablePath { get; init; }
    public string? CommandLine { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public string? WorkingDirectory { get; init; }
    /// <summary>Only JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS are ever extracted from the process environment.</summary>
    public IReadOnlyDictionary<string, string> JavaEnvironment { get; init; } = new Dictionary<string, string>();
    public string? ParentName { get; init; }
    public string? ParentPath { get; init; }
    /// <summary>Why the command line / working directory could not be read, if applicable.</summary>
    public string? ReadError { get; init; }
}

/// <summary>Enumerates running Java processes and reads their launch state (command line, working directory, JVM option variables).</summary>
public static partial class ProcessInspector
{
    public static readonly string[] JavaOptionVariables = ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];

    public static IReadOnlyList<JavaProcessInfo> EnumerateJava()
    {
        var list = new List<JavaProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process WHERE Name='javaw.exe' OR Name='java.exe'");
            foreach (ManagementObject o in searcher.Get())
            {
                var pid = Convert.ToInt32(o["ProcessId"]);
                var ppid = Convert.ToInt32(o["ParentProcessId"]);
                list.Add(Inspect(pid, ppid, (string)o["Name"], o["ExecutablePath"] as string, o["CommandLine"] as string, ParseWmiDate(o["CreationDate"] as string)));
            }
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or COMException)
        {
            foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                list.Add(new JavaProcessInfo { Pid = p.Id, Name = p.ProcessName + ".exe", ReadError = "Windows Management Instrumentation is unavailable, so the command line could not be read." });
        }
        return list;
    }

    /// <summary>Reads a single process (used by tests and by refresh of the selected process).</summary>
    public static JavaProcessInfo? Get(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process WHERE ProcessId={pid}");
            foreach (ManagementObject o in searcher.Get())
                return Inspect(pid, Convert.ToInt32(o["ParentProcessId"]), (string)o["Name"], o["ExecutablePath"] as string, o["CommandLine"] as string, ParseWmiDate(o["CreationDate"] as string));
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or COMException) { }
        return null;
    }

    private static JavaProcessInfo Inspect(int pid, int ppid, string name, string? exe, string? cmd, DateTimeOffset? started)
    {
        var (cwd, env, error) = ReadParameters(pid);
        string? parentName = null, parentPath = null;
        try
        {
            using var parent = Process.GetProcessById(ppid);
            // A recycled parent id would start after the child; ignore it in that case.
            if (started is null || parent.StartTime.ToUniversalTime() <= started.Value.UtcDateTime.AddSeconds(1))
            {
                parentName = parent.ProcessName;
                try { parentPath = parent.MainModule?.FileName; } catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
            }
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
        if (cmd is null) error ??= "The process command line could not be read (the game may be running with administrator rights while the scanner is not).";
        return new JavaProcessInfo
        {
            Pid = pid, ParentPid = ppid, Name = name, ExecutablePath = exe, CommandLine = cmd, StartedAt = started,
            WorkingDirectory = cwd, JavaEnvironment = env, ParentName = parentName, ParentPath = parentPath, ReadError = error,
        };
    }

    private static DateTimeOffset? ParseWmiDate(string? s)
    {
        if (s is null) return null;
        try { return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(s)); } catch (ArgumentOutOfRangeException) { return null; }
    }

    // ------------------------------------------------------------------ PEB access

    private const int ProcessBasicInformation = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public nint ExitStatus;
        public nint PebBaseAddress;
        public nint AffinityMask;
        public nint BasePriority;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, out PROCESS_BASIC_INFORMATION info, int length, out int returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWow64Process(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool wow64);

    // x64 layout offsets (PEB.ProcessParameters and RTL_USER_PROCESS_PARAMETERS).
    private const int PebProcessParameters = 0x20;
    private const int ParamsCurrentDirectory = 0x38;
    private const int ParamsEnvironment = 0x80;
    private const int ParamsEnvironmentSize = 0x3F0;

    /// <summary>
    /// Reads the working directory and the JVM option variables of another process from its process
    /// parameters block. Read-only (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ); works for processes of the
    /// same user, or any process when elevated.
    /// </summary>
    public static unsafe (string? Cwd, IReadOnlyDictionary<string, string> Env, string? Error) ReadParameters(int pid)
    {
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!Environment.Is64BitProcess) return (null, env, "The scanner must run as a 64-bit process to read process parameters.");
        using var h = Windows.Native.OpenProcess(Windows.Native.PROCESS_QUERY_INFORMATION | Windows.Native.PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) return (null, env, $"The game process could not be opened for reading (Windows error {Marshal.GetLastPInvokeError()}). If the game runs as administrator, run the scanner as administrator too.");
        if (IsWow64Process(h, out var wow) && wow) return (null, env, "The game runs on a 32-bit Java runtime; its working directory cannot be read.");
        if (NtQueryInformationProcess(h, ProcessBasicInformation, out var pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) != 0 || pbi.PebBaseAddress == 0)
            return (null, env, "The process information block could not be queried.");
        var parameters = ReadPointer(h, pbi.PebBaseAddress + PebProcessParameters);
        if (parameters == 0) return (null, env, "The process parameters could not be read.");

        string? cwd = ReadUnicodeString(h, parameters + ParamsCurrentDirectory);
        var envPtr = ReadPointer(h, parameters + ParamsEnvironment);
        var envSize = (long)ReadPointer(h, parameters + ParamsEnvironmentSize);
        if (envPtr != 0)
        {
            var size = (int)Math.Clamp(envSize <= 0 ? 64 * 1024 : envSize, 2, 1024 * 1024);
            var bytes = ReadBytes(h, envPtr, size);
            if (bytes is not null) ExtractJavaOptions(Encoding.Unicode.GetString(bytes), env);
        }
        return (cwd?.TrimEnd('\\') is { Length: > 0 } c ? (c.Length == 2 && c[1] == ':' ? c + "\\" : c) : null, env, null);
    }

    /// <summary>Parses a NUL-separated environment block, keeping only the JVM option variables.</summary>
    internal static void ExtractJavaOptions(string block, Dictionary<string, string> into)
    {
        foreach (var entry in block.Split('\0'))
        {
            if (entry.Length == 0) continue;
            var eq = entry.IndexOf('=', 1);
            if (eq <= 0) continue;
            var key = entry[..eq];
            if (JavaOptionVariables.Contains(key, StringComparer.OrdinalIgnoreCase)) into[key.ToUpperInvariant()] = entry[(eq + 1)..];
        }
    }

    private static unsafe nint ReadPointer(SafeProcessHandle h, nint address)
    {
        nint value = 0;
        return Windows.Native.ReadProcessMemory(h, address, (byte*)&value, sizeof(nint), out var read) && read == sizeof(nint) ? value : 0;
    }

    private static unsafe byte[]? ReadBytes(SafeProcessHandle h, nint address, int size)
    {
        var buffer = new byte[size];
        fixed (byte* p = buffer)
        {
            if (!Windows.Native.ReadProcessMemory(h, address, p, size, out var read) || read <= 0) return null;
            return read == size ? buffer : buffer[..(int)read];
        }
    }

    private static unsafe string? ReadUnicodeString(SafeProcessHandle h, nint address)
    {
        ushort length = 0;
        if (!Windows.Native.ReadProcessMemory(h, address, (byte*)&length, 2, out _) || length == 0 || length > 32767 * 2) return null;
        var buffer = ReadPointer(h, address + 8);
        if (buffer == 0) return null;
        var bytes = ReadBytes(h, buffer, length);
        return bytes is null ? null : Encoding.Unicode.GetString(bytes);
    }

    // ------------------------------------------------------------------ command line

    [LibraryImport("shell32.dll", EntryPoint = "CommandLineToArgvW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CommandLineToArgv(string commandLine, out int count);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);

    /// <summary>Splits a command line exactly as the Windows C runtime does.</summary>
    public static string[] SplitCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return [];
        var argv = CommandLineToArgv(commandLine, out var count);
        if (argv == 0) return [];
        try
        {
            var result = new string[count];
            for (var i = 0; i < count; i++) result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * nint.Size)) ?? "";
            return result;
        }
        finally { LocalFree(argv); }
    }
}
