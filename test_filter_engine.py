from core.file_loader import FileLoader
from core.string_extractor import StringExtractor
from core.filter_engine import FilterEngine

loader = FileLoader()
extractor = StringExtractor(min_length=3)
filter_engine = FilterEngine(min_length=3)

data = loader.load_file("hello.exe")

strings = extractor.extract_all_strings(data)

scored = filter_engine.filter_strings(strings)

print("=== TOP SUSPICIOUS STRINGS ===")
for s, score in scored[:10]:
    print(f"[{score}] {s}")