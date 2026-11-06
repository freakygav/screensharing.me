using System.Buffers.Binary;
using System.Text;

namespace Screensharing.Scanner.Windows;

public sealed record RecycledItem(string IndexFile, string OriginalPath, long Size, DateTime DeletedAt, string? ContentFile);

/// <summary>Parses $I index files of the Windows Recycle Bin (Vista: v1, Windows 10+: v2).</summary>
public static class RecycleBinParser
{
    public static RecycledItem Parse(string indexFile, byte[] data)
    {
        if (data.Length < 24) throw new InvalidDataException("Truncated $I file.");
        var version = BinaryPrimitives.ReadInt64LittleEndian(data);
        var size = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(8));
        var deleted = DateTime.FromFileTimeUtc(BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16)));
        string path;
        if (version == 2)
        {
            var len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(24));
            if (len <= 0 || 28 + len * 2 > data.Length) throw new InvalidDataException("Bad path length.");
            path = Encoding.Unicode.GetString(data, 28, len * 2).TrimEnd('\0');
        }
        else if (version == 1)
        {
            path = Encoding.Unicode.GetString(data, 24, Math.Min(520, data.Length - 24)).Split('\0')[0];
        }
        else throw new InvalidDataException($"Unknown $I version {version}.");
        var dir = Path.GetDirectoryName(indexFile)!;
        var content = Path.Combine(dir, "$R" + Path.GetFileName(indexFile)[2..]);
        return new RecycledItem(indexFile, path, size, deleted, File.Exists(content) ? content : null);
    }
}
