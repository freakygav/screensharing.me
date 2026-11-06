using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Screensharing.Scanner.Windows;

internal static partial class Native
{
    public const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_VM_READ = 0x0010;
    public const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_MAPPED = 0x40000, MEM_IMAGE = 0x1000000;
    public const uint PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint VirtualQueryEx(SafeProcessHandle h, nint address, out MEMORY_BASIC_INFORMATION info, nint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool ReadProcessMemory(SafeProcessHandle h, nint address, byte* buffer, nint size, out nint read);

    // ---- compression (Prefetch MAM) ----
    public const ushort COMPRESSION_FORMAT_XPRESS_HUFF = 4;
    public const ushort COMPRESSION_ENGINE_STANDARD = 0;

    [LibraryImport("ntdll.dll")]
    public static partial uint RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkspace, out uint fragmentWorkspace);

    [LibraryImport("ntdll.dll")]
    public static unsafe partial uint RtlDecompressBufferEx(ushort format, byte* uncompressed, uint uncompressedSize, byte* compressed, uint compressedSize, out uint finalSize, byte* workspace);

    [LibraryImport("ntdll.dll")]
    public static unsafe partial uint RtlCompressBuffer(ushort format, byte* uncompressed, uint uncompressedSize, byte* compressed, uint compressedSize, uint chunkSize, out uint finalSize, byte* workspace);

    // ---- volumes / USN ----
    public const uint GENERIC_READ = 0x80000000, FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4, OPEN_EXISTING = 3;
    public const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4, FSCTL_READ_USN_JOURNAL = 0x000900BB;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool DeviceIoControl(SafeFileHandle h, uint code, void* inBuf, int inSize, void* outBuf, int outSize, out int returned, nint overlapped);

    [StructLayout(LayoutKind.Sequential)]
    public struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ID_DESCRIPTOR
    {
        public uint dwSize;
        public int Type; // 0 = FileIdType
        public long FileId;
        public long Pad; // union padding (GUID/128-bit id)
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeFileHandle OpenFileById(SafeFileHandle volume, ref FILE_ID_DESCRIPTOR id, uint access, uint share, nint security, uint flags);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    public static unsafe partial uint GetFinalPathNameByHandle(SafeFileHandle h, char* buffer, uint size, uint flags);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool GetVolumeInformation(string root, char* name, int nameSize, out uint serial, out uint maxComponent, out uint flags, char* fs, int fsSize);
}
