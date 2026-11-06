using System.Buffers.Binary;
using System.Text;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Tests;

public class ArtifactParserTests
{
    /// <summary>Builds a minimal Windows 10 (version 30) SCCA prefetch body.</summary>
    internal static byte[] BuildScca30(string exe, uint runCount, DateTime[] runs, string[] files, uint serial = 0x1234ABCD)
    {
        var strings = Encoding.Unicode.GetBytes(string.Join("\0", files) + "\0");
        const int stringsOffset = 0x130;
        var device = Encoding.Unicode.GetBytes(@"\VOLUME{01d9a7b7f6a9d2c4-1234abcd}");
        var volOffset = stringsOffset + strings.Length;
        var buf = new byte[volOffset + 96 + device.Length + 64];
        BinaryPrimitives.WriteInt32LittleEndian(buf, 30);
        Encoding.ASCII.GetBytes("SCCA").CopyTo(buf, 4);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12), buf.Length);
        Encoding.Unicode.GetBytes(exe).CopyTo(buf, 0x10);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x54), 0x130); // metrics offset -> layout variant 1
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x64), stringsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x68), strings.Length);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x6C), volOffset);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x70), 1);
        for (var i = 0; i < runs.Length; i++) BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(0x80 + i * 8), runs[i].ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0xD0), runCount);
        strings.CopyTo(buf, stringsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(volOffset), 96); // device path offset (relative)
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(volOffset + 4), device.Length / 2);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(volOffset + 16), serial);
        device.CopyTo(buf, volOffset + 96);
        return buf;
    }

    [Fact]
    public void Parses_uncompressed_and_mam_compressed_prefetch()
    {
        var t1 = new DateTime(2026, 11, 5, 18, 30, 0, DateTimeKind.Utc);
        var t2 = t1.AddHours(-3);
        var scca = BuildScca30("JAVAW.EXE", 7, [t1, t2], [@"\VOLUME{01d9a7b7f6a9d2c4-1234abcd}\USERS\BOB\DOWNLOADS\DOOMSDAY.JAR", @"\VOLUME{01d9a7b7f6a9d2c4-1234abcd}\WINDOWS\SYSTEM32\NTDLL.DLL"]);

        foreach (var bytes in new[] { scca, PrefetchParser.Compress(scca) })
        {
            var info = PrefetchParser.Parse(bytes);
            Assert.Equal("JAVAW.EXE", info.ExecutableName);
            Assert.Equal(30, info.Version);
            Assert.Equal(7u, info.RunCount);
            Assert.Equal([t1, t2], info.LastRunTimes);
            Assert.Contains(info.ReferencedFiles, f => f.EndsWith("DOOMSDAY.JAR"));
            Assert.Equal(0x1234ABCDu, info.Volumes.Single().Serial);
        }
        Assert.Equal((byte)'M', PrefetchParser.Compress(scca)[0]);
    }

    [Fact]
    public void Resolves_prefetch_volume_paths_to_drive_letters()
    {
        var map = new Dictionary<uint, string> { [0x1234ABCD] = "D:" };
        var path = Modules.ExecutionModule.ResolvePath(@"\VOLUME{01d9a7b7f6a9d2c4-1234abcd}\USERS\BOB\X.JAR", [(@"\VOLUME{01d9a7b7f6a9d2c4-1234abcd}", 0x1234ABCDu)], map);
        Assert.Equal(@"D:\USERS\BOB\X.JAR", path);
    }

    [Fact]
    public void Rejects_non_prefetch_data()
    {
        Assert.Throws<InvalidDataException>(() => PrefetchParser.Parse(new byte[200]));
    }

    [Fact]
    public void Parses_recycle_bin_v2_index()
    {
        var path = @"C:\Users\bob\AppData\Roaming\.minecraft\mods\meteor-client.jar";
        var name = Encoding.Unicode.GetBytes(path + "\0");
        var data = new byte[28 + name.Length];
        BinaryPrimitives.WriteInt64LittleEndian(data, 2);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(8), 123456);
        var deleted = new DateTime(2026, 11, 4, 12, 0, 0, DateTimeKind.Utc);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(16), deleted.ToFileTimeUtc());
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(24), path.Length + 1);
        name.CopyTo(data, 28);
        var item = RecycleBinParser.Parse(@"C:\$Recycle.Bin\S-1\$IABC123.jar", data);
        Assert.Equal(path, item.OriginalPath);
        Assert.Equal(123456, item.Size);
        Assert.Equal(deleted, item.DeletedAt);
    }

    [Fact]
    public void Aho_corasick_finds_overlapping_patterns()
    {
        var ac = new AhoCorasick(["meteordevelopment/meteorclient", "KillAura", "Aura"]);
        var data = Encoding.ASCII.GetBytes("xx meteordevelopment/meteorclient/systems KillAura yy");
        var hits = ac.Search(data).ToList();
        Assert.Contains(hits, h => h.Pattern == 0 && h.Position == 3);
        Assert.Contains(hits, h => h.Pattern == 1);
        Assert.Contains(hits, h => h.Pattern == 2);
    }

    [Fact]
    public void Memory_scanner_reads_a_live_process()
    {
        var marker = "ssme-memory-marker/" + Guid.NewGuid().ToString("N");
        var bytes = Encoding.ASCII.GetBytes(marker); // keep a copy alive in this process's heap
        var res = MemoryScanner.Scan(Environment.ProcessId, [marker], 4L << 30, TimeSpan.FromSeconds(60), CancellationToken.None);
        GC.KeepAlive(bytes);
        Assert.Null(res.Error);
        Assert.True(res.Hits.ContainsKey(marker));
        Assert.True(res.BytesScanned > 0);
    }

    [Fact]
    public void Module_heuristic_ignores_ordinary_mod_classes()
    {
        var legit = new[] { "net/caffeinemc/sodium/render/Renderer", "com/mod/world/Speed", "com/mod/player/Reach", "com/mod/Velocity", "com/mod/client/gui/Screen" };
        var r = ModuleHeuristics.Evaluate(legit);
        Assert.Empty(r.Names);
        var cheat = ModuleHeuristics.Evaluate(["x/module/combat/KillAura", "x/module/combat/Velocity", "x/module/movement/Speed", "x/module/combat/KillAura$1"]);
        Assert.Equal(3, cheat.Names.Count);
        Assert.Equal(1, cheat.HighSignalCount);
    }
}
