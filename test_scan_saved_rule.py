from core.controller import Controller
from database.db import Database

controller = Controller()
db = Database()

# Show saved rules
rules = db.get_rules()

print("=== SAVED RULES ===")
for r in rules:
    print(r["id"], "-", r["name"], "- source:", r["source_file_name"])

if not rules:
    print("No saved rules found. Generate and save a rule first.")
else:
    rule_id = int(input("\nEnter rule id: "))
    target_file = input("Enter target file to scan: ")

    result = controller.scan_file_with_saved_rule(target_file, rule_id)

    if isinstance(result, dict) and result.get("success") == False:
        print("Error:", result["message"])
    else:
        print("\n=== SCAN RESULT ===")
        print("Status:", result.status())
        print("Matched:", result.is_matched)
        print("Matched rules:", result.matched_rules)
        print("Details:", result.details)