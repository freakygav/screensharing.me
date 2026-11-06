namespace Screensharing.Scanner.Analysis;

/// <summary>
/// Detects the "module system" layout used by hacked clients: one class per cheat feature
/// (KillAura, Scaffold, …), often grouped into combat/movement/render packages.
/// </summary>
public static class ModuleHeuristics
{
    /// <summary>Names that are essentially never used by legitimate mods for a class.</summary>
    public static readonly HashSet<string> HighSignal = new(StringComparer.OrdinalIgnoreCase)
    {
        "KillAura", "AimAssist", "AimBot", "TriggerBot", "AutoClicker", "CrystalAura", "AutoCrystal", "AnchorAura", "BedAura",
        "Scaffold", "ScaffoldWalk", "AntiKnockback", "AntiKB", "Criticals", "AutoTotem", "ChestESP", "PlayerESP", "StorageESP",
        "BowAimbot", "NoFall", "LongJump", "HighJump", "Jesus", "Nuker", "FastPlace", "AutoArmor", "AutoPot", "AutoSoup",
        "NoSlow", "NoSlowdown", "ElytraFly", "BoatFly", "AntiBot", "Spider", "Surround", "HoleFiller", "AutoAnchor", "TpAura",
        "InfiniteAura", "MultiAura", "SilentAura", "WTap", "AutoWTap", "HitSelect", "BlockHit",
    };

    /// <summary>Ambiguous names: counted only inside module-like packages.</summary>
    public static readonly HashSet<string> Ambiguous = new(StringComparer.OrdinalIgnoreCase)
    {
        "Velocity", "Reach", "Fly", "Flight", "Speed", "Timer", "XRay", "ESP", "Freecam", "Tracers", "Step", "Blink",
        "Sprint", "HitBoxes", "Hitbox", "Fullbright", "Nametags", "AutoTool", "Phase", "Glide", "NoClip", "AirJump",
    };

    private static readonly string[] ModuleSegments =
    [
        "module", "modules", "feature", "features", "hack", "hacks", "cheat", "cheats",
        "combat", "movement", "render", "visual", "visuals", "exploit", "exploits",
    ];

    public sealed record Result(IReadOnlyList<string> Names, int HighSignalCount, IReadOnlyList<string> Examples);

    public static Result Evaluate(IEnumerable<string> classPaths)
    {
        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var examples = new List<string>();
        var high = 0;
        foreach (var path in classPaths)
        {
            var slash = path.LastIndexOf('/');
            var simple = path[(slash + 1)..];
            if (simple.Contains('$')) continue; // inner classes duplicate their outer class
            var stripped = StripSuffix(simple);
            var segments = slash > 0 ? path[..slash].Split('/') : [];
            var moduleLike = segments.Any(s => ModuleSegments.Contains(s, StringComparer.OrdinalIgnoreCase));
            bool counted = false;
            if (HighSignal.Contains(stripped)) { if (names.Add(stripped)) { high++; counted = true; } }
            else if (moduleLike && Ambiguous.Contains(stripped)) { counted = names.Add(stripped); }
            if (counted && examples.Count < 12) examples.Add(path);
        }
        return new Result(names.ToList(), high, examples);
    }

    private static string StripSuffix(string simple)
    {
        foreach (var suffix in new[] { "Module", "Hack", "Feature", "Mod", "Cheat" })
            if (simple.Length > suffix.Length + 2 && simple.EndsWith(suffix, StringComparison.Ordinal))
                return simple[..^suffix.Length];
        return simple;
    }
}
