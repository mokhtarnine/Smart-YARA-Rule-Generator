from core.behavior_tagger import BehaviorTagger

tagger = BehaviorTagger()

scored_strings = [
    ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 15),
    ("http://badsite.com/payload.exe", 20),
    ("User-Agent: Mozilla/5.0", 10),
    ("cmd.exe /c whoami", 12),
    ("powershell -enc abc123", 18),
    ("VirtualAlloc", 14),
    ("GetProcAddress", 14),
    ("CreateFileA", 8),
    ("WriteFile", 8),
    ("IsDebuggerPresent", 11),
    ("normal harmless string", 0),
]

behaviors = tagger.detect(scored_strings)

print("Detected behaviors:")
print("=" * 50)

for behavior in behaviors:
    print("Name:", behavior.name)
    print("Severity:", behavior.severity)
    print("Reason:", behavior.reason)
    print("Indicators:")

    for indicator in behavior.indicators:
        print("  -", indicator)

    print("-" * 50)