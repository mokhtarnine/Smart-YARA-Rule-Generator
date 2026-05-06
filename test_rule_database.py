from models.rule import Rule
from database.db import Database

db = Database()

rule = Rule(
    name="TestSavedRule",
    content="rule TestSavedRule { condition: true }",
    author="Mokhtar",
    description="Testing saved rule table"
)

source_file_info = {
    "file_name": "m1.exe",
    "file_path": "m1.exe",
    "file_size": 20480
}

db.save_rule(rule, source_file_info)

print("Rule saved.")

rules = db.get_rules()

print("\n=== SAVED RULES ===")
for r in rules:
    print(r["id"], "-", r["name"], "- source:", r["source_file_name"])

first_rule_id = rules[0]["id"]

full_rule = db.get_rule_by_id(first_rule_id)

print("\n=== FULL RULE ===")
print(full_rule)
