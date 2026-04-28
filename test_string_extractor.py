from core.file_loader import FileLoader
from core.string_extractor import StringExtractor

loader = FileLoader()
extractor = StringExtractor(min_length=3)

try:
    data = loader.load_file("m1.exe")

    strings = extractor.extract_all_strings(data)

    print(f"Total strings found: {len(strings)}\n")

    print("=== ALL STRINGS ===")
    for s in strings[:15]:
        print("-", s)

    #   Show only interesting ones
    interesting = extractor.filter_interesting(strings)

    print("\n=== INTERESTING STRINGS ===")
    for s in interesting:
        print("-", s)

except Exception as e:
    print("Error:", e)