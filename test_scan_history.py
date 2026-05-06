from database.db import Database

db = Database()

history = db.get_scan_history()

print("=== SCAN HISTORY ===")

if not history:
    print("No scan history found.")
else:
    for item in history:
        print("ID:", item["id"])
        print("Rule:", item["rule_name"])
        print("Target:", item["target_file_name"])
        print("Matched:", item["is_matched"])
        print("Matched rules:", item["matched_rules"])
        print("Date:", item["scanned_at"])
        print("----------------------")
