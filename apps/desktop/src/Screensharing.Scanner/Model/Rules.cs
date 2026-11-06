using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Screensharing.Scanner.Model;

public sealed class DetectionRule
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = "";
    public string Category { get; init; } = "";
    public required string Kind { get; init; }
    public required string Pattern { get; init; }
    public string? Family { get; init; }
    public List<string> Features { get; init; } = [];
    public string Severity { get; init; } = "INFO";
    public string Tier { get; init; } = "INCONCLUSIVE";
    public int Confidence { get; init; }
    public string? Classification { get; init; }
    public string FalsePositives { get; init; } = "";
    public string Limitations { get; init; } = "";
    public List<string> References { get; init; } = [];

    /// <summary>For STRING rules: where the string is matched (see <see cref="SignatureScope"/>).</summary>
    public List<string> Scopes { get; init; } = [];

    /// <summary>Contribution to the per-file family score (0 = derived from the tier).</summary>
    public int Weight { get; init; }

    /// <summary>For KNOWN_MOD rules: class packages every genuine build ships (impersonation check).</summary>
    public List<string> Packages { get; init; } = [];

    [JsonIgnore] public Severity SeverityValue => EnumText.ParseSeverity(Severity);
    [JsonIgnore] public EvidenceTier TierValue => EnumText.ParseTier(Tier);

    /// <summary>Generic indicators are only reported in combination and never as confirmed.</summary>
    [JsonIgnore] public bool IsIndicator => string.Equals(Classification, "indicator", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public int EffectiveWeight => Weight > 0 ? Weight : TierValue switch
    {
        EvidenceTier.ConfirmedArtifact => 100,
        EvidenceTier.StrongIndicator => 60,
        EvidenceTier.SuspiciousConfiguration => 40,
        EvidenceTier.WeakIndicator => 25,
        _ => 0,
    };

    private Regex? _regex;
    private bool _regexFailed;

    /// <summary>Compiled regex for *_REGEX rules (.NET syntax). Invalid patterns are ignored, never thrown.</summary>
    public Regex? Regex
    {
        get
        {
            if (_regex is null && !_regexFailed)
            {
                try { _regex = new Regex(Pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)); }
                catch (ArgumentException) { _regexFailed = true; }
            }
            return _regex;
        }
    }

    public bool IsMatch(string input)
    {
        try { return Regex?.IsMatch(input) ?? false; }
        catch (RegexMatchTimeoutException) { return false; }
    }
}

public static class RuleKind
{
    public const string ModId = "MOD_ID", ModIdRegex = "MOD_ID_REGEX", PackagePrefix = "PACKAGE_PREFIX", MemoryString = "MEMORY_STRING",
        String = "STRING", Sha256 = "SHA256", InstancePathRegex = "INSTANCE_PATH_REGEX", ExecutableRegex = "EXECUTABLE_REGEX",
        FileNameRegex = "FILE_NAME_REGEX", ResourcePackRegex = "RESOURCEPACK_REGEX", ShaderPackRegex = "SHADERPACK_REGEX",
        FeatureName = "FEATURE_NAME", ModulePackage = "MODULE_PACKAGE", KnownMod = "KNOWN_MOD", LibraryPackage = "LIBRARY_PACKAGE",
        Builtin = "BUILTIN";
}

/// <summary>Where a STRING signature is matched.</summary>
public static class SignatureScope
{
    public const string Class = "class", Resource = "resource", Config = "config", Log = "log", Script = "script", Binary = "binary", Memory = "memory";
}

/// <summary>Built-in heuristic rule ids (catalog entries with kind BUILTIN).</summary>
public static class Builtin
{
    public const string ModuleClasses = "SSME-H-MODULE_CLASSES";
    public const string JavaAgentManifest = "SSME-H-JAVA_AGENT_MANIFEST";
    public const string ObfuscatedArchive = "SSME-H-OBFUSCATED_ARCHIVE";
    public const string DisguisedArchive = "SSME-H-DISGUISED_ARCHIVE";
    public const string NonJarArchive = "SSME-H-NON_JAR_ARCHIVE";
    public const string DuplicateModId = "SSME-H-DUPLICATE_MOD_ID";
    public const string UnrecognizedMod = "SSME-H-UNRECOGNIZED_MOD";
    public const string ClientJarModified = "SSME-H-CLIENT_JAR_MODIFIED";
    public const string LibraryModified = "SSME-H-LIBRARY_MODIFIED";
    public const string LoggedModMissing = "SSME-H-LOGGED_MOD_MISSING";
    public const string LoggedCheatMod = "SSME-H-LOGGED_CHEAT_MOD";
    public const string JavaAgentArgument = "SSME-H-JAVAAGENT_ARGUMENT";
    public const string JavaOptionsEnv = "SSME-H-JAVA_OPTIONS_ENV";
    public const string UnsignedModule = "SSME-H-UNSIGNED_MODULE";
    public const string MemoryFeatureCluster = "SSME-H-MEMORY_FEATURE_CLUSTER";
    public const string ModChangedAfterSession = "SSME-H-MOD_CHANGED_AFTER_SESSION";
    public const string EncryptedClasses = "SSME-H-ENCRYPTED_CLASSES";
    public const string EmbeddedExecutable = "SSME-H-EMBEDDED_EXECUTABLE";
    public const string PolyglotArchive = "SSME-H-POLYGLOT_ARCHIVE";
    public const string ExecutableInInstance = "SSME-H-EXECUTABLE_IN_INSTANCE";
    public const string ModImpersonation = "SSME-H-MOD_IMPERSONATION";
    public const string MetadataInconsistent = "SSME-H-METADATA_INCONSISTENT";
    public const string XrayTextures = "SSME-H-XRAY_TEXTURES";
    public const string ClasspathUnexpected = "SSME-H-CLASSPATH_UNEXPECTED";
    public const string LinkedFolder = "SSME-H-LINKED_FOLDER";
    public const string Uninspectable = "SSME-H-UNINSPECTABLE";
}

public sealed class RuleSet
{
    public string Version { get; init; } = "unversioned";
    public List<DetectionRule> Rules { get; init; } = [];

    private Dictionary<string, DetectionRule>? _byId;
    private ILookup<string, DetectionRule>? _byKind;
    private HashSet<string>? _highSignal, _ambiguous, _segments;
    private string[]? _libraryPackages;

    public DetectionRule? Get(string id) => (_byId ??= Rules.GroupBy(r => r.Id).ToDictionary(g => g.Key, g => g.First())).GetValueOrDefault(id);
    public IEnumerable<DetectionRule> OfKind(string kind) => (_byKind ??= Rules.ToLookup(r => r.Kind))[kind];

    public DetectionRule? KnownMod(string modId) => OfKind(RuleKind.KnownMod).FirstOrDefault(r => string.Equals(r.Pattern, modId, StringComparison.OrdinalIgnoreCase));

    /// <summary>Cheat/utility mod ids (MOD_ID rules) — used to recognise cheat mods in logs.</summary>
    public DetectionRule? ModIdRule(string modId) => OfKind(RuleKind.ModId).FirstOrDefault(r => string.Equals(r.Pattern, modId, StringComparison.OrdinalIgnoreCase));

    public IReadOnlySet<string> HighSignalFeatures => _highSignal ??= Set(OfKind(RuleKind.FeatureName).Where(r => r.Classification == "high-signal"));
    /// <summary>Feature names distinctive enough to search for in game memory.</summary>
    public IReadOnlySet<string> MemoryFeatures => _memory ??= Set(OfKind(RuleKind.FeatureName).Where(r => r.Scopes.Contains(SignatureScope.Memory, StringComparer.OrdinalIgnoreCase)));
    private HashSet<string>? _memory;
    public IReadOnlySet<string> AmbiguousFeatures => _ambiguous ??= Set(OfKind(RuleKind.FeatureName).Where(r => r.Classification == "ambiguous"));
    public IReadOnlySet<string> ModuleSegments => _segments ??= Set(OfKind(RuleKind.ModulePackage));
    public IReadOnlyList<string> LibraryPackages => _libraryPackages ??= OfKind(RuleKind.LibraryPackage).Select(r => r.Pattern).ToArray();

    private static HashSet<string> Set(IEnumerable<DetectionRule> rules) => new(rules.Select(r => r.Pattern), StringComparer.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    public static RuleSet Parse(string json) => JsonSerializer.Deserialize<RuleSet>(json, Json) ?? new RuleSet();

    /// <summary>The ruleset compiled into this build (fallback when the server catalog is unavailable).</summary>
    public static RuleSet LoadEmbedded()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Screensharing.Scanner.rules.json")
            ?? throw new InvalidOperationException("Embedded ruleset missing");
        using var r = new StreamReader(s);
        return Parse(r.ReadToEnd());
    }
}
