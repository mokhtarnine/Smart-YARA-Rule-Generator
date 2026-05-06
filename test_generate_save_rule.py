from core.controller import Controller

controller = Controller()

source_file = "hello.exe"
rule_name = "MySavedRule2"

try:
    rule = controller.generate_and_save_rule(source_file, rule_name)

    if isinstance(rule, dict) and rule.get("success") == False:
        print("Error:", rule["message"])
        print(rule["rule"])
    else:
        print("Rule generated and saved.")
        print("Rule name:", rule.name)
        print("\n=== RULE CONTENT ===")
        print(rule.content)

except Exception as e:
    print("Error:", e)
