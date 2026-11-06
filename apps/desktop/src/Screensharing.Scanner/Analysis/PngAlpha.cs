using System.Buffers.Binary;
using System.IO.Compression;

namespace Screensharing.Scanner.Analysis;

/// <summary>Decodes a PNG far enough to measure how much of the image is fully transparent (used for X-ray texture detection).</summary>
public static class PngAlpha
{
    private static readonly byte[] Signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>Fraction (0..1) of pixels with alpha = 0, or null if the PNG cannot be decoded.</summary>
    public static double? TransparentFraction(byte[] png)
    {
        try
        {
            if (png.Length < 33 || !png.AsSpan(0, 8).SequenceEqual(Signature)) return null;
            int width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
            byte[]? trns = null;
            using var idat = new MemoryStream();
            var pos = 8;
            while (pos + 8 <= png.Length)
            {
                var len = (int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(pos));
                var type = System.Text.Encoding.ASCII.GetString(png, pos + 4, 4);
                if (len < 0 || pos + 12 + len > png.Length) return null;
                var data = png.AsSpan(pos + 8, len);
                switch (type)
                {
                    case "IHDR":
                        width = (int)BinaryPrimitives.ReadUInt32BigEndian(data);
                        height = (int)BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
                        bitDepth = data[8]; colorType = data[9]; interlace = data[12];
                        break;
                    case "tRNS": trns = data.ToArray(); break;
                    case "IDAT": idat.Write(data); break;
                }
                if (type == "IEND") break;
                pos += 12 + len;
            }
            if (width <= 0 || height <= 0 || width > 4096 || height > 4096 || bitDepth != 8 || interlace != 0) return null;
            var channels = colorType switch { 6 => 4, 4 => 2, 2 => 3, 0 => 1, 3 => 1, _ => 0 };
            if (channels == 0) return null;
            if (colorType is 0 or 2) return trns is null ? 0 : null; // fully opaque unless a colour key is used
            var stride = width * channels;
            var raw = new byte[(stride + 1) * height];
            idat.Position = 0;
            using (var z = new ZLibStream(idat, CompressionMode.Decompress))
            {
                var read = 0;
                while (read < raw.Length) { var n = z.Read(raw, read, raw.Length - read); if (n <= 0) break; read += n; }
                if (read < raw.Length) return null;
            }
            var prev = new byte[stride];
            var cur = new byte[stride];
            long transparent = 0;
            for (var y = 0; y < height; y++)
            {
                var filter = raw[y * (stride + 1)];
                Array.Copy(raw, y * (stride + 1) + 1, cur, 0, stride);
                Unfilter(filter, cur, prev, channels);
                for (var x = 0; x < width; x++)
                {
                    var alpha = colorType switch
                    {
                        6 => cur[x * 4 + 3],
                        4 => cur[x * 2 + 1],
                        _ => trns is not null && cur[x] < trns.Length ? trns[cur[x]] : (byte)255, // palette
                    };
                    if (alpha == 0) transparent++;
                }
                (prev, cur) = (cur, prev);
            }
            return (double)transparent / ((long)width * height);
        }
        catch (Exception e) when (e is InvalidDataException or ArgumentException or IndexOutOfRangeException) { return null; }
    }

    private static void Unfilter(byte filter, byte[] cur, byte[] prev, int bpp)
    {
        for (var i = 0; i < cur.Length; i++)
        {
            int a = i >= bpp ? cur[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
            cur[i] = filter switch
            {
                1 => (byte)(cur[i] + a),
                2 => (byte)(cur[i] + b),
                3 => (byte)(cur[i] + ((a + b) >> 1)),
                4 => (byte)(cur[i] + Paeth(a, b, c)),
                _ => cur[i],
            };
        }
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }
}
