from core.controller import Controller

controller = Controller()

file_path = "data.exe"

try:
    result = controller.analyze_file(file_path)

    print("*** CONTROLLER TEST ****")
    print("Success:", result.status())

    print("\n*** FILE INFO ****")
    print(result.file_info)

    print("\n *** TOTAL STRINGS ****")
    print(result.total_strings())

    print("\n **** TOP SCORED STRINGS ****")
    for s, score in result.top_strings(10):
        print(f"[{score}] {s}")

    print("\n*** GENERATED RULE ***")
    print(result.rule.content)

    print("\n*** SCAN RESULT ***")
    print(result.scan_result.to_dict())

except Exception as e:
    print("Error:", e)