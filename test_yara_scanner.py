from core.file_loader import FileLoader
from core.string_extractor import StringExtractor
from core.filter_engine import FilterEngine
from core.rule_generator import RuleGenerator
from core.yara_scanner import YaraScanner

file_path = "hello.exe"

loader = FileLoader()
extractor = StringExtractor(min_length=3)
filter_engine = FilterEngine(min_length=3)
rule_generator = RuleGenerator(rule_name="TestRule", author="Mokhtar")
scanner = YaraScanner()

try :
    # load file
    data = loader.load_file(file_path)
    # Extract strings
    strings = extractor.extract_all_strings(data)
    print("Total strings found:", len(strings))
    #filter and score strings
    scored_strings = filter_engine.filter_strings(strings)

    print("\n=== TOP STRINGS ===")
    for s, score in scored_strings[:10]:
        print(f"[{score}] {s}")

    # generate YARA rule
    rule = rule_generator.generate_rule(scored_strings)
    print("\n=== GENERATED YARA RULE ===")
    print(rule)

    # validate rule
    is_valid = scanner.validate_rule(rule)
    print("\nRule valid:", is_valid)

    #scan file
    if is_valid:
        result = scanner.scan(file_path, rule)

        print("\n=== SCAN RESult")
        print("Matched:",result["is_matched"])
        print("Matched rules:", result["matched_rules"])
        print("Details:", result["details"])

except Exception as e:
    print("Error:",e)
