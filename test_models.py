from models.rule import Rule
from models.scan_result import ScanResult
from models.analysis import AnalysisResult

# 1. Test Rule model
rule_content = """
rule TestRule
{
    strings:
        $s1 = "cmd.exe"
    condition:
        $s1
}
"""

rule = Rule(
    name="TestRule",
    content=rule_content,
    author="Mokhtar",
    description="Test generated YARA rule"
)

print("=== RULE MODEL ===")
print("Name:", rule.name)
print("Author:", rule.author)
print("Is empty:", rule.is_empty())
print("Rule dict:", rule.to_dict())

# 2. Test ScanResult model
scan = ScanResult(
    is_matched=True,
    matched_rules=["TestRule"],
    details="[TestRule]"
)

print("\n=== SCAN RESULT MODEL ===")
print("Is matched:", scan.is_matched)
print("Matched rules:", scan.matched_rules)
print("Has matches:", scan.has_matches())
print("Status:", scan.status())
print("Scan dict:", scan.to_dict())

# 3. Test AnalysisResult model
analysis = AnalysisResult(
    file_info={
        "file_name": "m1.exe",
        "file_size": 20480,
        "file_path": "m1.exe"
    },
    strings=[
        "cmd.exe",
        "https://bad-c2.com",
        "KERNEL32.dll"
    ],
    scored_strings=[
        ("https://bad-c2.com", 20),
        ("cmd.exe", 19),
        ("KERNEL32.dll", 5)
    ],
    rule=rule,
    scan_result=scan
)

print("\n=== ANALYSIS RESULT MODEL ===")
print("File name:", analysis.file_info["file_name"])
print("Total strings:", analysis.total_strings())
print("Top strings:", analysis.top_strings(2))
print("Status:", analysis.status())
print("Analysis dict:", analysis.to_dict())
