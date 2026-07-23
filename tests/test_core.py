import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.behavior_tagger import BehaviorTagger
from core.file_loader import FileLoader
from core.filter_engine import FilterEngine
from core.rule_generator import RuleGenerator
from core.string_extractor import StringExtractor
from core.yara_scanner import YaraScanner


class FileLoaderTests(unittest.TestCase):
    def setUp(self):
        self.loader = FileLoader()

    def test_load_file_records_data_and_file_info(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"payload")

            self.assertEqual(self.loader.load_file(str(path)), b"payload")
            self.assertEqual(
                self.loader.get_file_info(),
                {"file_name": "sample.bin", "file_size": 7, "file_path": str(path)},
            )

    def test_missing_file_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            self.loader.load_file("definitely-missing.bin")

    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "not a file"):
                self.loader.load_file(directory)

    def test_file_over_50_mb_is_rejected_before_reading(self):
        with tempfile.NamedTemporaryFile() as sample, patch(
            "core.file_loader.os.path.getsize", return_value=50 * 1024 * 1024 + 1
        ):
            with self.assertRaisesRegex(ValueError, "too large"):
                self.loader.load_file(sample.name)

    def test_clear_resets_state(self):
        self.loader.file_path = "sample.bin"
        self.loader.file_data = b"data"
        self.loader.clear()
        self.assertEqual(self.loader.get_file_info(), {})
        self.assertIsNone(self.loader.file_data)


class StringExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = StringExtractor(min_length=4)

    def test_extracts_ascii_strings(self):
        self.assertEqual(self.extractor.extract_ascii_strings(b"\x01hello world\x00abc"), ["hello world"])

    def test_extracts_utf16le_strings(self):
        data = b"prefix\x01" + "PowerShell".encode("utf-16le") + b"\x01"
        self.assertIn("PowerShell", self.extractor.extract_utf16_strings(data))

    def test_extracts_literal_backslash_zero_strings(self):
        data = rb"noise h\0t\0t\0p\0 tail"
        self.assertIn("http", self.extractor.extract_fake_unicode(data))

    def test_extract_all_deduplicates_cleans_and_sorts(self):
        data = b"beta\x00alpha\x00beta\x01" + "wide".encode("utf-16le")
        result = self.extractor.extract_all_strings(data)
        self.assertEqual(result, sorted(set(result)))
        self.assertIn("alpha", result)
        self.assertIn("beta", result)
        self.assertIn("wide", result)


class FilterEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = FilterEngine()

    def test_remove_noise(self):
        result = self.engine.remove_noise(["abc", "aaaa", "!!!!", " useful value "])
        self.assertEqual(result, ["useful value"])

    def test_detects_supported_indicator_types(self):
        cases = {
            "https://example.com": "url",
            "connect 192.168.1.20": "ip",
            "cmd.exe /c whoami": "command",
            "HKEY_CURRENT_USER": "registry",
            "kernel32.dll": "dll",
            "dropper.exe": "exe",
            "VirtualAlloc": "api",
            "ordinary text": "other",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.engine.detect_type(value), expected)

    def test_filter_sorts_highest_score_first(self):
        result = self.engine.filter_strings(["normal text", "https://evil.example/payload.exe", "VirtualAlloc"])
        self.assertEqual(result[0][0], "https://evil.example/payload.exe")
        self.assertGreaterEqual(result[0][1], result[1][1])

    def test_get_top_strings_discards_scores(self):
        self.assertEqual(self.engine.get_top_strings([("one", 10), ("two", 5)], 1), ["one"])


class BehaviorTaggerTests(unittest.TestCase):
    def test_detects_multiple_behaviors_and_deduplicates_indicators(self):
        indicators = [
            ("cmd.exe /c powershell", 20),
            ("https://evil.example/download", 20),
            ("cmd.exe /c powershell", 20),
            "VirtualAlloc and WriteProcessMemory",
        ]
        behaviors = BehaviorTagger().detect(indicators)
        by_name = {behavior.name: behavior for behavior in behaviors}

        self.assertIn("Command execution", by_name)
        self.assertIn("Network / Downloader", by_name)
        self.assertIn("Injection / Runtime loading", by_name)
        self.assertEqual(by_name["Command execution"].indicators, ["cmd.exe /c powershell"])

    def test_no_indicators_returns_empty_list(self):
        self.assertEqual(BehaviorTagger().detect([("ordinary text", 0)]), [])


class RuleGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.generator = RuleGenerator("Bad rule-name!", 'A "quoted" author')

    def test_sanitizes_rule_name_and_escapes_strings(self):
        self.assertEqual(self.generator.rule_name, "Bad_rule_name_")
        self.assertEqual(self.generator.escape_string('C:\\Temp\\"x"'), 'C:\\\\Temp\\\\\\"x\\"')

    def test_select_strings_uses_scores_and_fallback(self):
        scored = [("high", 10), ("low", 0), ("medium", 3)]
        self.assertEqual(self.generator.select_strings(scored), ["high", "low", "medium"])
        self.assertEqual(self.generator.select_strings([(str(i), 5) for i in range(30)], 2), ["0", "1"])

    def test_build_condition_boundaries(self):
        expected = {0: "false", 1: "$s1", 2: "any of them", 3: "any of them", 4: "2 of them", 5: "2 of them"}
        for count, condition in expected.items():
            self.assertEqual(self.generator.build_condition(count), condition)

    def test_generated_rule_has_metadata_modifiers_and_valid_syntax(self):
        rule = self.generator.generate_rule(
            [("https://evil.example", 15), ("dropper.exe", 10), ("cmd.exe /c whoami", 10)]
        )
        self.assertIn("rule Bad_rule_name_", rule)
        self.assertIn("nocase ascii", rule)
        self.assertIn("ascii wide", rule)
        self.assertIn("condition:\n        any of them", rule)
        self.assertTrue(YaraScanner().validate_rule(rule))


class YaraScannerTests(unittest.TestCase):
    RULE = 'rule FindMarker { strings: $marker = "malicious-marker" condition: $marker }'

    def test_validates_valid_and_invalid_rules(self):
        scanner = YaraScanner()
        self.assertTrue(scanner.validate_rule(self.RULE))
        self.assertFalse(scanner.validate_rule("rule broken { condition: }"))

    def test_scan_reports_match_and_no_match(self):
        scanner = YaraScanner()
        with tempfile.TemporaryDirectory() as directory:
            matching = Path(directory) / "matching.bin"
            clean = Path(directory) / "clean.bin"
            matching.write_bytes(b"prefix malicious-marker suffix")
            clean.write_bytes(b"ordinary content")

            hit = scanner.scan(str(matching), self.RULE)
            miss = scanner.scan(str(clean), self.RULE)

        self.assertTrue(hit["is_matched"])
        self.assertEqual(hit["matched_rules"], ["FindMarker"])
        self.assertFalse(miss["is_matched"])
        self.assertEqual(miss["matched_rules"], [])

    def test_scan_returns_structured_error_for_invalid_rule(self):
        result = YaraScanner().scan("missing.bin", "rule broken { condition: }")
        self.assertFalse(result["is_matched"])
        self.assertIn("Invalid YARA rule", result["details"])


if __name__ == "__main__":
    unittest.main()
