from models.rule import Rule
from models.scan_result import ScanResult
from models.analysis import AnalysisResult
from database.db import Database

# 1. Create fake rule
rule = Rule(
    name="TestRule",
    content="rule TestRule { condition: true }",
    author="Mokhtar",
    description="Fake rule for database test"
)

# 2. Create fake scan result
scan = ScanResult(
    is_matched=True,
    matched_rules=["TestRule"],
    details="[TestRule]"
)

# 3. Create fake full analysis result
analysis = AnalysisResult(
    file_info={
        "file_name": "m1.exe",
        "file_path": "m1.exe",
        "file_size": 20480
    },
    strings=["cmd.exe", "https://bad-c2.com"],
    scored_strings=[
        ("https://bad-c2.com", 20),
        ("cmd.exe", 19)
    ],
    rule=rule,
    scan_result=scan
)

# 4. Create database object
db = Database()

# 5. Save analysis
db.save_analysis(analysis)

print("Analysis saved successfully.")

# 6. Read history
history = db.get_history()

print("\n=== DATABASE HISTORY ===")
for item in history:
    print("ID:", item["id"])
    print("File:", item["file_name"])
    print("Status:", item["status"])
    print("Matched rules:", item["matched_rules"])
    print("Rule:", item["rule_name"])
    print("Date:", item["analyzed_at"])
    print("----------------------")
