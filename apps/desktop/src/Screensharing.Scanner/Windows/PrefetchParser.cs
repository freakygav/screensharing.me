using System.Buffers.Binary;
using System.Text;

namespace Screensharing.Scanner.Windows;

public sealed record PrefetchInfo(string ExecutableName, int Version, uint RunCount, IReadOnlyList<DateTime> LastRunTimes, IReadOnlyList<string> ReferencedFiles, IReadOnlyList<(string Device, uint Serial)> Volumes);

/// <summary>
/// Parser for Windows Prefetch (.pf) files: SCCA versions 17/23/26/30/31 and the
/// Windows 8.1+ "MAM" compressed container (XPRESS Huffman, decompressed with ntdll).
/// </summary>
public static class PrefetchParser
{
    public static PrefetchInfo Parse(byte[] raw)
    {
        var data = raw.Length >= 8 && raw[0] == (byte)'M' && raw[1] == (byte)'A' && raw[2] == (byte)'M' ? Decompress(raw) : raw;
        if (data.Length < 0x54 || Encoding.ASCII.GetString(data, 4, 4) != "SCCA") throw new InvalidDataException("Not a prefetch file (missing SCCA signature).");
        var version = BinaryPrimitives.ReadInt32LittleEndian(data);
        var exe = Encoding.Unicode.GetString(data, 0x10, 60).Split('\0')[0];

        var stringsOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x64));
        var stringsSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x68));
        var volOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x6C));
        var volCount = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x70));
        var metricsOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x54));

        var times = new List<DateTime>();
        uint runCount;
        switch (version)
        {
            case 17:
                AddTime(data, 0x78, times);
                runCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x90));
                break;
            case 23:
                AddTime(data, 0x80, times);
                runCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x98));
                break;
            case 26:
            case 30:
            case 31:
                for (var i = 0; i < 8; i++) AddTime(data, 0x80 + i * 8, times);
                // Windows 10/11 have two layouts; the metrics offset (0x130 vs 0x128) tells which.
                var runOffset = version == 26 ? 0xD0 : metricsOffset == 0x128 ? 0xC8 : 0xD0;
                runCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(runOffset));
                break;
            default:
                throw new InvalidDataException($"Unsupported prefetch version {version}.");
        }

        var files = new List<string>();
        if (stringsOffset > 0 && stringsSize > 0 && stringsOffset + stringsSize <= data.Length)
            files.AddRange(Encoding.Unicode.GetString(data, stringsOffset, stringsSize).Split('\0', StringSplitOptions.RemoveEmptyEntries));

        var volumes = new List<(string, uint)>();
        for (var v = 0; v < volCount && volOffset > 0; v++)
        {
            var baseOff = volOffset + v * (version >= 30 ? 96 : version == 26 ? 104 : 40);
            if (baseOff + 20 > data.Length) break;
            var devOff = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(baseOff));
            var devLen = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(baseOff + 4));
            var serial = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(baseOff + 16));
            var abs = volOffset + devOff;
            var dev = abs > 0 && abs + devLen * 2 <= data.Length ? Encoding.Unicode.GetString(data, abs, devLen * 2) : "";
            volumes.Add((dev, serial));
        }
        return new PrefetchInfo(exe, version, runCount, times, files, volumes);
    }

    private static void AddTime(byte[] d, int off, List<DateTime> times)
    {
        var ft = BinaryPrimitives.ReadInt64LittleEndian(d.AsSpan(off));
        if (ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc()) times.Add(DateTime.FromFileTimeUtc(ft));
    }

    public static unsafe byte[] Decompress(byte[] raw)
    {
        var size = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4));
        if (size is 0 or > 64 * 1024 * 1024) throw new InvalidDataException("Implausible decompressed prefetch size.");
        if (Native.RtlGetCompressionWorkSpaceSize(Native.COMPRESSION_FORMAT_XPRESS_HUFF, out var ws, out _) != 0) throw new InvalidDataException("Compression workspace unavailable.");
        var output = new byte[size];
        var workspace = new byte[ws];
        fixed (byte* o = output) fixed (byte* c = &raw[8]) fixed (byte* w = workspace)
        {
            var status = Native.RtlDecompressBufferEx(Native.COMPRESSION_FORMAT_XPRESS_HUFF, o, size, c, (uint)(raw.Length - 8), out var final, w);
            if (status != 0) throw new InvalidDataException($"RtlDecompressBufferEx failed (0x{status:X8}).");
            if (final != size) Array.Resize(ref output, (int)final);
        }
        return output;
    }

    /// <summary>Builds a MAM container (used by tests to produce realistic compressed fixtures).</summary>
    public static unsafe byte[] Compress(byte[] scca)
    {
        if (Native.RtlGetCompressionWorkSpaceSize(Native.COMPRESSION_FORMAT_XPRESS_HUFF, out var ws, out _) != 0) throw new InvalidOperationException();
        var outBuf = new byte[scca.Length + 4096];
        var workspace = new byte[ws];
        uint final;
        fixed (byte* u = scca) fixed (byte* o = outBuf) fixed (byte* w = workspace)
        {
            var st = Native.RtlCompressBuffer(Native.COMPRESSION_FORMAT_XPRESS_HUFF, u, (uint)scca.Length, o, (uint)outBuf.Length, 4096, out final, w);
            if (st != 0) throw new InvalidOperationException($"RtlCompressBuffer failed 0x{st:X8}");
        }
        var mam = new byte[8 + final];
        mam[0] = (byte)'M'; mam[1] = (byte)'A'; mam[2] = (byte)'M'; mam[3] = 0x04;
        BinaryPrimitives.WriteUInt32LittleEndian(mam.AsSpan(4), (uint)scca.Length);
        Array.Copy(outBuf, 0, mam, 8, final);
        return mam;
    }
}
