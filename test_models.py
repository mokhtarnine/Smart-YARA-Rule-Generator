from core.behavior_tagger import BehaviorTagger

tagger = BehaviorTagger()

scored_strings = [
    ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 15),
    ("http://badsite.com/payload.exe", 20),
    ("cmd.exe /c whoami", 12),
    ("VirtualAlloc", 10),
]

behaviors = tagger.detect(scored_strings)

for behavior in behaviors:
    print(behavior.summary())
    print(behavior.to_dict())