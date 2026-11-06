using System.Buffers.Binary;

namespace Screensharing.Scanner.Analysis;

/// <summary>
/// Minimal reader for Java class files: validates the header and extracts the CONSTANT_Utf8 entries of the
/// constant pool (class and member names, descriptors and string literals). Nothing is loaded or executed.
/// </summary>
public static class ClassFile
{
    public const uint Magic = 0xCAFEBABE;

    public static bool HasMagic(ReadOnlySpan<byte> data) => data.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(data) == Magic;

    /// <summary>
    /// Writes the raw modified-UTF-8 bytes of every Utf8 constant into <paramref name="sink"/>, separated by NUL
    /// bytes so that a signature can never match across two constants. Returns false for malformed files.
    /// </summary>
    public static bool ExtractUtf8Constants(ReadOnlySpan<byte> data, Stream sink)
    {
        if (!HasMagic(data) || data.Length < 10) return false;
        var count = BinaryPrimitives.ReadUInt16BigEndian(data[8..]);
        var pos = 10;
        for (var i = 1; i < count; i++)
        {
            if (pos >= data.Length) return false;
            var tag = data[pos++];
            switch (tag)
            {
                case 1: // Utf8
                    if (pos + 2 > data.Length) return false;
                    var len = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
                    pos += 2;
                    if (pos + len > data.Length) return false;
                    sink.Write(data.Slice(pos, len));
                    sink.WriteByte(0);
                    pos += len;
                    break;
                case 3: case 4: pos += 4; break;               // Integer, Float
                case 5: case 6: pos += 8; i++; break;          // Long, Double take two slots
                case 7: case 8: case 16: case 19: case 20: pos += 2; break; // Class, String, MethodType, Module, Package
                case 9: case 10: case 11: case 12: case 17: case 18: pos += 4; break; // refs, NameAndType, Dynamic, InvokeDynamic
                case 15: pos += 3; break;                      // MethodHandle
                default: return false;
            }
        }
        return true;
    }
}
