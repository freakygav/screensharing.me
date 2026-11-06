using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Screensharing.Scanner.Windows;

public sealed record UsnRecord(long Usn, DateTime Time, uint Reason, string FileName, long FileRef, long ParentRef);

/// <summary>Reads the NTFS change journal of a volume (requires administrator rights). Read-only.</summary>
public static class UsnJournal
{
    public const uint REASON_FILE_DELETE = 0x00000200, REASON_RENAME_OLD_NAME = 0x00001000, REASON_RENAME_NEW_NAME = 0x00002000, REASON_FILE_CREATE = 0x00000100;

    public static unsafe IEnumerable<UsnRecord> Read(string driveLetter, DateTime since, Func<string, bool> nameFilter, long maxBytes, CancellationToken ct)
    {
        using var vol = Native.CreateFile($@"\\.\{driveLetter.TrimEnd('\\', ':')}:", Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, 0, Native.OPEN_EXISTING, 0, 0);
        if (vol.IsInvalid) throw new UnauthorizedAccessException($"Cannot open volume {driveLetter} (error {Marshal.GetLastPInvokeError()}).");
        Native.USN_JOURNAL_DATA_V0 jd;
        if (!Native.DeviceIoControl(vol, Native.FSCTL_QUERY_USN_JOURNAL, null, 0, &jd, sizeof(Native.USN_JOURNAL_DATA_V0), out _, 0))
            throw new InvalidOperationException($"No change journal on {driveLetter} (error {Marshal.GetLastPInvokeError()}).");

        var results = new List<UsnRecord>();
        var req = new Native.READ_USN_JOURNAL_DATA_V0 { StartUsn = jd.FirstUsn, ReasonMask = 0xFFFFFFFF, UsnJournalID = jd.UsnJournalID };
        var buffer = new byte[1 << 20];
        long total = 0;
        fixed (byte* b = buffer)
        {
            while (total < maxBytes)
            {
                ct.ThrowIfCancellationRequested();
                if (!Native.DeviceIoControl(vol, Native.FSCTL_READ_USN_JOURNAL, &req, sizeof(Native.READ_USN_JOURNAL_DATA_V0), b, buffer.Length, out var got, 0) || got <= 8) break;
                total += got;
                var next = BinaryPrimitives.ReadInt64LittleEndian(buffer);
                var off = 8;
                while (off + 60 <= got)
                {
                    var len = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(off));
                    if (len <= 0 || off + len > got) break;
                    var major = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(off + 4));
                    if (major == 2)
                    {
                        var fileRef = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(off + 8));
                        var parentRef = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(off + 16));
                        var usn = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(off + 24));
                        var ts = DateTime.FromFileTimeUtc(BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(off + 32)));
                        var reason = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(off + 40));
                        var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(off + 56));
                        var nameOff = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(off + 58));
                        if (ts >= since && off + nameOff + nameLen <= got)
                        {
                            var name = Encoding.Unicode.GetString(buffer, off + nameOff, nameLen);
                            if (nameFilter(name)) results.Add(new UsnRecord(usn, ts, reason, name, fileRef, parentRef));
                        }
                    }
                    off += len;
                }
                if (next == req.StartUsn) break;
                req.StartUsn = next;
            }
        }
        return results;
    }

    /// <summary>Resolves a directory's current path from its file reference number (only works while it still exists).</summary>
    public static unsafe string? ResolveDirectory(string driveLetter, long fileRef)
    {
        using var vol = Native.CreateFile($@"\\.\{driveLetter.TrimEnd('\\', ':')}:", Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, 0, Native.OPEN_EXISTING, 0, 0);
        if (vol.IsInvalid) return null;
        var desc = new Native.FILE_ID_DESCRIPTOR { dwSize = (uint)sizeof(Native.FILE_ID_DESCRIPTOR), Type = 0, FileId = fileRef };
        using var h = Native.OpenFileById(vol, ref desc, 0, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, 0, Native.FILE_FLAG_BACKUP_SEMANTICS);
        if (h.IsInvalid) return null;
        var buf = stackalloc char[1024];
        var n = Native.GetFinalPathNameByHandle(h, buf, 1024, 0);
        if (n == 0 || n >= 1024) return null;
        var s = new string(buf, 0, (int)n);
        return s.StartsWith(@"\\?\", StringComparison.Ordinal) ? s[4..] : s;
    }
}
