from core.controller import Controller

def main():
    print("********* Smart YARA Rule Genrator **************")

    file_path = input("Enter file path to analyze: ")

    controller = Controller()

    try:
        result = controller.analyze_file(file_path)

        print("\n*** ANALYSIS RESULT ***")
        print("file:", result.file_info["file_name"])
        print("status:", result.status())
        print("Total strings:", result.total_strings())

        print("\n *** TOP SUSPICIOUS STRINGS ***")
        for s, score in result.top_strings(10):
            print(f"[{score}] {s}")

        print("\n **** GENERATED YARA RULE ****")
        print(result.rule.content)

        print("\n ***  SCAN RESULT ***")
        print("MATCHED :",result.scan_result.is_matched)
        print("MATCHED RULES :",result.scan_result.matched_rules)
        print("DETAILS:", result.scan_result.details)

    except Exception as e:
        print("Error:",e)

if __name__ == "__main__":
    main()