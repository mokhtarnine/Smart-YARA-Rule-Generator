from core.controller import Controller

def show_menu():
    print("\n ************** SMART YARA RULE GENERATOR *************")
    print("1. Generate and save YARA rule")
    print("2. Scan file with saved rule")
    print("3. Show saved rules ")
    print("4. show scan history ")
    print("5. Exist")

def generate_rule(controller):
    source_file = input("Enter source file path:")
    rule_name = input("enter rule name :")

    result = controller.generate_and_save_rule(source_file, rule_name)

    if isinstance(result, dict) and result.get("success") == False:
        print("Error:", result["message"])
        print(result.get("rule", ""))
        return
    
    print("\n Rule generated and saved successfully.")
    print("Rule name:", result.name)
    print("\n ****** GENERATED RULE *********")
    print(result.content)

def scan_file(controller):
    rules = controller.get_saved_rules()

    if not rules :
        print("No saved rules found. Generate a rule first.")
        return
    
    print("\n *** SAVED RULES ***")
    for rule in rules:
        print(rule["id"], "-", rule["name"], "- source:", rule["source_file_name"])
    
    rule_id = int(input("\n Enter rule id :"))
    target_file = input("Enter target file path:")

    result = controller.scan_file_with_saved_rule(target_file,rule_id)

    if isinstance(result, dict) and result.get("success") == False:
        print("Error ", result["message"])
        return
    
    print("\n *** SCAN RESULT ***")
    print("Status :", result.status())
    print("Matched:",result.matched_rules)
    print("Details:", result.details)

def show_saved_rules(controller):
    rules = controller.get_saved_rules()

    print("\n *** SAVED RULES ***")

    if not rules:
        print("No saved Rules found.")
        return
    
    for rule in rules:
        print("ID:", rule["id"])
        print("Name:", rule["name"])
        print("Author", rule["author"])
        print("Source file:", rule["source_file_name"])
        print("Created at:", rule["created_at"])
        print("-------------------------------")

def show_scan_history(controller):
    history = controller.get_scan_history()

    print("\n **** SCAN HISTORY ****")

    if not history:
        print("No scan history found")
        return
    
    for item in history:
        print("ID:", item["id"])
        print("Rule:", item["rule_name"])
        print("Target:", item["target_file_name"])
        print("Matched rules:", item["matched_rules"])
        print("Date:", item["scanned_at"])
        print("*************************")


def main():
    controller = Controller()

    while True:
        show_menu()

        choice = input("choose option: ")

        

        try :
            if choice == "1":
                generate_rule(controller)

            elif choice == "2":
                scan_file(controller)

            elif choice == "3":
                show_saved_rules(controller)

            elif choice == "4":
                show_scan_history(controller)

            elif choice == "5":
                print("Exit.")
                break

        except Exception as e:
            print("Error:",e)

if __name__ == "__main__":
    main()