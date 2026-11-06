using System.Diagnostics;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;
using static Screensharing.Scanner.Tests.TestUtil;

namespace Screensharing.Scanner.Tests;

/// <summary>The scan must stay inside the selected instance: other instances and the rest of the computer are never read.</summary>
public class ScopeTests
{
    private static void PlantCheatsOutsideTheInstance(FixtureBuilder fx)
    {
        fx.AddMod("meteor-client-0.5.8.jar", Meteor, Path.Combine(fx.OtherInstance, "mods"));
        Directory.CreateDirectory(Path.Combine(fx.OtherInstance, "meteor-client"));
        fx.AddMod("wurst.jar", Wurst, Path.Combine(fx.Unrelated, "Downloads"));
        fx.AddText("Documents/notes.txt", "net.wurstclient. meteor-client.mixins.json CreateRemoteThread", fx.Unrelated);
        fx.AddFile("Downloads/injector.exe", FixtureBuilder.BuildPe("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "JNI_GetCreatedJavaVMs"), fx.Unrelated);
    }

    [Fact]
    public async Task Only_the_selected_instance_is_inspected()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddMod("sodium-fabric-0.6.0.jar", Sodium);
        fx.AddText("config/sodium-options.json", "{\"quality\":{}}");
        PlantCheatsOutsideTheInstance(fx);

        var r = await Scan(fx);

        Assert.Empty(r.Findings);
        Assert.Empty(r.ScopeViolations);
        var allowedFiles = new HashSet<string>(fx.ClassPath.Concat(fx.ClassPath.Select(c => Path.ChangeExtension(c, ".json"))), StringComparer.OrdinalIgnoreCase);
        Assert.NotEmpty(r.AccessedPaths);
        foreach (var p in r.AccessedPaths)
            Assert.True(p.StartsWith(fx.InstanceRoot, StringComparison.OrdinalIgnoreCase) || allowedFiles.Contains(p), $"accessed outside the instance: {p}");
        Assert.DoesNotContain(r.AccessedPaths, p => p.StartsWith(fx.OtherInstance, StringComparison.OrdinalIgnoreCase) || p.StartsWith(fx.Unrelated, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(r.Custody, o => o.Target.Contains(fx.OtherInstance, StringComparison.OrdinalIgnoreCase) || o.Target.Contains(fx.Unrelated, StringComparison.OrdinalIgnoreCase));
        Assert.All(r.Mods, m => Assert.StartsWith(fx.InstanceRoot, (string)m["path"]!, StringComparison.OrdinalIgnoreCase));
        var inst = Assert.Single(r.Installations);
        Assert.Equal(fx.GameDir, inst["path"]);
        // The launcher-shared libraries folder was not enumerated: only the class-path entries themselves.
        Assert.DoesNotContain(r.AccessedPaths, p => p.Equals(Path.Combine(fx.Launcher, "libraries"), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scope_refuses_files_outside_the_instance()
    {
        using var fx = new FixtureBuilder();
        var outside = fx.AddText("Documents/private.txt", "secret", fx.Unrelated);
        var scope = ScanEngine.BuildScope(fx.Target());
        Assert.True(scope.Contains(Path.Combine(fx.GameDir, "mods", "x.jar")));
        Assert.True(scope.Contains(Path.Combine(fx.InstanceRoot, "instance.cfg")));
        Assert.False(scope.Contains(outside));
        Assert.False(scope.Contains(Path.Combine(fx.OtherInstance, "mods")));
        Assert.False(scope.Contains(fx.InstanceRoot + "-evil\\x.jar")); // prefix trick
        Assert.False(scope.Contains(Path.Combine(fx.GameDir, "..", "..", "Other", ".minecraft", "options.txt"))); // traversal
        Assert.Throws<ScopeViolationException>(() => scope.Demand(outside, "read"));
        Assert.Single(scope.Violations);
    }

    [Fact]
    public async Task Links_out_of_the_instance_are_not_followed_except_loaded_content_folders()
    {
        using var fx = new FixtureBuilder();
        PlantCheatsOutsideTheInstance(fx);
        // A junction from the instance's config folder to the user's documents must not be followed.
        FixtureBuilder.Junction(Path.Combine(fx.GameDir, "config", "docs"), Path.Combine(fx.Unrelated, "Documents"));
        // The mods folder redirected elsewhere IS loaded by the game, so it is followed and reported.
        var shared = Path.Combine(fx.Root, "SharedMods");
        Directory.CreateDirectory(shared);
        fx.AddMod("wurst-renamed.jar", Wurst, shared);
        Directory.Delete(fx.Mods);
        FixtureBuilder.Junction(fx.Mods, shared);

        var r = await Scan(fx);

        Assert.Empty(r.ScopeViolations);
        Assert.Contains(r.InspectionRecords, x => x.Status == InspectionStatus.LinkNotFollowed && x.Location == "config/docs/");
        Assert.DoesNotContain(r.AccessedPaths, p => p.StartsWith(fx.Unrelated, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.LinkedFolder && f.Location == "mods/");
        var wurst = Assert.Single(r.Findings.Where(f => f.Family == "Wurst Client"));
        Assert.Equal("mods/wurst-renamed.jar", wurst.Location);
    }

    [Fact]
    public async Task An_unresolved_instance_is_refused_instead_of_falling_back()
    {
        using var fx = new FixtureBuilder();
        var target = new GameInstance
        {
            Launcher = "Unknown", Name = "javaw.exe (PID 1)", GameDirectory = "", InstanceRoot = "", GameDirectorySource = "unknown",
            Resolved = false, Problem = "The game was started without a --gameDir argument and its working directory could not be read.",
        };
        var engine = new ScanEngine(new ScanOptions { Rules = Rules, Target = target, ModrinthLookup = false, MemoryScan = false });
        var e = await Assert.ThrowsAsync<InstanceNotResolvedException>(() => engine.RunAsync());
        Assert.Contains("--gameDir", e.Message);
    }

    // ------------------------------------------------------------- instance identification

    private static JavaProcessInfo Proc(string cmd, string? cwd = null, string? parent = null) => new()
    {
        Pid = 4242, Name = "javaw.exe", CommandLine = cmd, WorkingDirectory = cwd, ParentName = parent, StartedAt = DateTimeOffset.UtcNow,
        ExecutablePath = @"C:\Java\bin\javaw.exe",
    };

    [Fact]
    public void Modrinth_app_instance_is_identified_from_gameDir_and_class_path()
    {
        using var fx = new FixtureBuilder();
        var profile = Path.Combine(fx.Root, "ModrinthApp", "profiles", "sarni modpack");
        Directory.CreateDirectory(Path.Combine(profile, "logs"));
        var meta = Path.Combine(fx.Root, "ModrinthApp", "meta");
        var cmd = $"\"C:\\Java\\bin\\javaw.exe\" -Xmx4G -Djava.library.path={meta}\\natives\\1.21.11 -Dminecraft.launcher.brand=theseus -Dminecraft.launcher.version=0.23.1 " +
                  $"-cp C:\\Temp\\.tmpX\\theseus.jar;{meta}\\libraries\\net\\fabricmc\\fabric-loader\\0.17.2\\fabric-loader-0.17.2.jar;{meta}\\versions\\1.21.11-0.20.1\\1.21.11-0.20.1.jar " +
                  $"--add-opens=java.base/java.lang.reflect=ALL-UNNAMED com.modrinth.theseus.MinecraftLaunch net.fabricmc.loader.impl.launch.knot.KnotClient --username Steve --version 1.21.11 " +
                  $"--gameDir \"{profile}\" --assetsDir {meta}\\assets --uuid 1234 --accessToken eyJ.secret.token --versionType release";
        var i = InstanceResolver.Resolve(Proc(cmd, cwd: profile))!;
        Assert.True(i.Resolved, i.Problem);
        Assert.Equal("Modrinth App", i.Launcher);
        Assert.Equal("sarni modpack", i.Name);
        Assert.Equal(profile, i.GameDirectory);
        Assert.Equal("--gameDir argument", i.GameDirectorySource);
        Assert.Equal("1.21.11", i.MinecraftVersion);
        Assert.Equal("Fabric", i.Loader);
        Assert.Equal("net.fabricmc.loader.impl.launch.knot.KnotClient", i.MainClass);
        Assert.Equal(3, i.ClassPath.Count);
        Assert.Contains(i.LibraryRoots, r => r.EndsWith(@"meta\libraries", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("eyJ.secret.token", i.RedactedCommandLine);
        Assert.DoesNotContain("Steve", i.RedactedCommandLine);
    }

    [Fact]
    public void Prism_instance_is_identified_from_the_working_directory_and_instance_cfg()
    {
        using var fx = new FixtureBuilder();
        var cmd = $"\"C:\\Java\\bin\\javaw.exe\" -Xms512m -Xmx4096m -Djava.library.path={fx.InstanceRoot}\\natives -cp {fx.Root}\\PrismLauncher\\libraries\\NewLaunch.jar org.prismlauncher.EntryPoint";
        var i = InstanceResolver.Resolve(Proc(cmd, cwd: fx.GameDir, parent: "prismlauncher"))!;
        Assert.True(i.Resolved, i.Problem);
        Assert.Equal("Prism Launcher", i.Launcher);
        Assert.Equal("Selected PvP", i.Name);
        Assert.Equal(fx.GameDir, i.GameDirectory);
        Assert.Equal(fx.InstanceRoot, i.InstanceRoot);
        Assert.StartsWith("process working directory", i.GameDirectorySource);
    }

    [Fact]
    public void Official_launcher_and_curseforge_instances_are_identified()
    {
        using var fx = new FixtureBuilder();
        var official = Path.Combine(fx.Root, "AppData", ".minecraft");
        Directory.CreateDirectory(Path.Combine(official, "logs"));
        var i = InstanceResolver.Resolve(Proc($"javaw.exe -Dminecraft.launcher.brand=minecraft-launcher -cp a.jar net.minecraft.client.main.Main --version 1.21.4 --gameDir {official} --assetsDir x", parent: "MinecraftLauncher"))!;
        Assert.True(i.Resolved, i.Problem);
        Assert.Equal("Official Minecraft Launcher", i.Launcher);
        Assert.Equal("Vanilla", i.Loader);

        var cf = Path.Combine(fx.Root, "curseforge", "minecraft", "Instances", "All the Mods 10");
        Directory.CreateDirectory(Path.Combine(cf, "mods"));
        File.WriteAllText(Path.Combine(cf, "minecraftinstance.json"), "{\"name\":\"All the Mods 10\",\"gameVersion\":\"1.21.1\"}");
        var c = InstanceResolver.Resolve(Proc($"javaw.exe -Dminecraft.launcher.brand=minecraft-launcher -cp a.jar cpw.mods.bootstraplauncher.BootstrapLauncher --gameDir \"{cf}\" --version neoforge-21.1.77"))!;
        Assert.True(c.Resolved, c.Problem);
        Assert.Equal("CurseForge", c.Launcher);
        Assert.Equal("All the Mods 10", c.Name);
    }

    [Fact]
    public void Missing_information_is_reported_instead_of_guessed()
    {
        using var fx = new FixtureBuilder();
        // No --gameDir and no readable working directory.
        var a = InstanceResolver.Resolve(Proc("javaw.exe -cp x.jar net.minecraft.client.main.Main --version 1.21 --accessToken t"))!;
        Assert.False(a.Resolved);
        Assert.Contains("working directory could not be read", a.Problem);
        // A --gameDir that does not exist.
        var b = InstanceResolver.Resolve(Proc($"javaw.exe -cp x.jar net.minecraft.client.main.Main --gameDir {Path.Combine(fx.Root, "missing")}"))!;
        Assert.False(b.Resolved);
        Assert.Contains("does not exist", b.Problem);
        // A folder that is not a game directory.
        var c = InstanceResolver.Resolve(Proc($"javaw.exe -cp x.jar net.minecraft.client.main.Main --gameDir {fx.Unrelated}"))!;
        Assert.False(c.Resolved);
        Assert.Contains("does not look like a Minecraft game directory", c.Problem);
        // Command line unreadable.
        var d = InstanceResolver.Resolve(new JavaProcessInfo { Pid = 7, Name = "javaw.exe", ReadError = "access denied" })!;
        Assert.False(d.Resolved);
        Assert.Equal("access denied", d.Problem);
        // Other Java programs are not Minecraft at all.
        Assert.Null(InstanceResolver.Resolve(Proc("java.exe -jar C:\\tools\\gradle-wrapper.jar build")));
        Assert.Null(InstanceResolver.Resolve(Proc("javaw.exe -cp idea.jar com.intellij.idea.Main")));
    }

    [Fact]
    public void Working_directory_and_jvm_option_variables_are_read_from_a_live_process()
    {
        using var fx = new FixtureBuilder();
        var psi = new ProcessStartInfo("ping.exe", "-n 30 127.0.0.1") { WorkingDirectory = fx.GameDir, CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
        psi.Environment["JAVA_TOOL_OPTIONS"] = "-javaagent:C:\\evil\\agent.jar";
        psi.Environment["UNRELATED_SECRET"] = "must-not-be-read";
        using var p = Process.Start(psi)!;
        try
        {
            Thread.Sleep(300);
            var (cwd, env, error) = ProcessInspector.ReadParameters(p.Id);
            Assert.Null(error);
            Assert.Equal(fx.GameDir, cwd, ignoreCase: true);
            Assert.Equal("-javaagent:C:\\evil\\agent.jar", env["JAVA_TOOL_OPTIONS"]);
            Assert.Single(env); // nothing but the JVM option variables is extracted
        }
        finally { p.Kill(); }
    }

    [Fact]
    public void Command_line_secrets_are_redacted()
    {
        var cmd = "javaw.exe -Xmx4G -javaagent:C:\\a.jar net.minecraft.client.main.Main --username Steve --accessToken eyJhbGciOi.secret --uuid 1234 --gameDir C:\\mc";
        var red = InstanceResolver.Redact(cmd);
        Assert.DoesNotContain("eyJhbGciOi", red);
        Assert.DoesNotContain("Steve", red);
        Assert.Contains("--accessToken [redacted]", red);
        Assert.Contains("-javaagent:C:\\a.jar", red);
    }
}
