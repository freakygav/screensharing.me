namespace Screensharing.Scanner.Instance;

/// <summary>A parsed Java command line: JVM options, class path, main class and application (game) arguments.</summary>
public sealed class JavaLaunch
{
    public string? Executable { get; private init; }
    public List<string> JvmOptions { get; } = [];
    public List<string> ClassPath { get; } = [];
    public string? JarFile { get; private set; }
    public string? MainClass { get; private set; }
    /// <summary>Main class of the game when <see cref="MainClass"/> is a launcher wrapper (e.g. Modrinth's MinecraftLaunch).</summary>
    public string? EffectiveMainClass { get; private set; }
    public List<string> AppArgs { get; } = [];
    public Dictionary<string, string> SystemProperties { get; } = new(StringComparer.Ordinal);
    public List<(string Kind, string Value)> Agents { get; } = [];

    /// <summary>JVM options that take the next token as their value.</summary>
    private static readonly HashSet<string> OptionsWithValue = new(StringComparer.Ordinal)
    {
        "--add-opens", "--add-exports", "--add-reads", "--add-modules", "--module-path", "-p", "--patch-module", "--limit-modules", "--upgrade-module-path",
    };

    /// <summary>Launcher wrappers whose first application argument is the real main class.</summary>
    private static readonly HashSet<string> Wrappers = new(StringComparer.Ordinal) { "com.modrinth.theseus.MinecraftLaunch" };

    public static JavaLaunch Parse(IReadOnlyList<string> argv)
    {
        var l = new JavaLaunch { Executable = argv.Count > 0 ? argv[0] : null };
        var i = 1;
        for (; i < argv.Count; i++)
        {
            var a = argv[i];
            if (a is "-cp" or "-classpath" or "--class-path")
            {
                if (i + 1 < argv.Count) l.ClassPath.AddRange(argv[++i].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                continue;
            }
            if (a == "-jar")
            {
                if (i + 1 < argv.Count) { l.JarFile = argv[++i]; l.ClassPath.Add(l.JarFile); }
                i++;
                break;
            }
            if (a.StartsWith('-'))
            {
                l.JvmOptions.Add(a);
                if (OptionsWithValue.Contains(a) && i + 1 < argv.Count) { l.JvmOptions.Add(argv[++i]); continue; }
                if (a.StartsWith("-D", StringComparison.Ordinal))
                {
                    var eq = a.IndexOf('=');
                    if (eq > 2) l.SystemProperties[a[2..eq]] = a[(eq + 1)..];
                    else l.SystemProperties[a[2..]] = "";
                }
                foreach (var prefix in new[] { "-javaagent:", "-agentpath:", "-agentlib:" })
                    if (a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        l.Agents.Add((prefix.Trim('-', ':'), a[prefix.Length..]));
                continue;
            }
            l.MainClass = a;
            i++;
            break;
        }
        for (; i < argv.Count; i++) l.AppArgs.Add(argv[i]);
        l.EffectiveMainClass = l.MainClass;
        if (l.MainClass is not null && Wrappers.Contains(l.MainClass) && l.AppArgs.Count > 0 && !l.AppArgs[0].StartsWith('-'))
            l.EffectiveMainClass = l.AppArgs[0];
        return l;
    }

    /// <summary>Value of a game argument such as --gameDir or --version.</summary>
    public string? Arg(string name)
    {
        for (var i = 0; i < AppArgs.Count - 1; i++)
            if (string.Equals(AppArgs[i], name, StringComparison.OrdinalIgnoreCase)) return AppArgs[i + 1];
        foreach (var a in AppArgs)
            if (a.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase)) return a[(name.Length + 1)..];
        return null;
    }

    public bool HasArg(string name) => AppArgs.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase) || a.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase));
}
