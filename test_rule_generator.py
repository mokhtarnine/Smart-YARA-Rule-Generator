from core.file_loader import FileLoader
from core.string_extractor import StringExtractor
from core.filter_engine import FilterEngine
from core.rule_generator import RuleGenerator

loader = FileLoader()
extractor = StringExtractor(min_length=3)
filter_engine = FilterEngine(min_length=3)
generator = RuleGenerator(rule_name="malware_test",author = "you")

data = loader.load_file("hello.exe")

strings = extractor.extract_all_strings(data)
scored = filter_engine.filter_strings(strings)

rule = generator.generate_rule(scored)

print(rule)