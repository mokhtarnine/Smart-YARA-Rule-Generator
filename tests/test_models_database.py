import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from database.db import Database
from models.analysis import AnalysisResult
from models.behavior import BehaviorTag
from models.rule import Rule
from models.scan_result import ScanResult


class ModelTests(unittest.TestCase):
    def test_rule_and_behavior_serialization(self):
        rule = Rule("Example", "rule Example { condition: true }", "Analyst", "Description")
        behavior = BehaviorTag("Persistence", "Run key", "High", ["HKEY...Run"])

        self.assertFalse(rule.is_empty())
        self.assertEqual(rule.to_dict()["name"], "Example")
        self.assertEqual(behavior.summary(), "Persistence (High)")
        self.assertTrue(behavior.has_indicators())
        self.assertEqual(behavior.to_dict()["indicators"], ["HKEY...Run"])

    def test_scan_and_analysis_models(self):
        scan = ScanResult(True, ["Example"], "details")
        rule = Rule("Example", "content")
        analysis = AnalysisResult(
            {"file_name": "sample.bin", "file_path": "sample.bin", "file_size": 1},
            ["one", "two"],
            [("one", 10), ("two", 5)],
            rule,
            scan,
        )

        self.assertEqual(scan.status(), "Malicious /Suspicious")
        self.assertTrue(scan.has_matches())
        self.assertEqual(analysis.total_strings(), 2)
        self.assertEqual(analysis.top_strings(1), [("one", 10)])
        self.assertEqual(analysis.to_dict()["status"], "Malicious /Suspicious")


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test.db")
        self.database = Database(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_creates_all_tables(self):
        connection = sqlite3.connect(self.db_path)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            connection.close()
        self.assertTrue({"analysis_results", "rules", "scan_history"}.issubset(tables))

    def test_rule_round_trip_preserves_behaviors(self):
        rule = Rule("Example", "rule Example { condition: true }", "Analyst", "Test rule")
        behavior = BehaviorTag("Persistence", "Run key", "High", ["HKEY...Run"])
        source = {"file_name": "sample.bin", "file_path": "C:/sample.bin", "file_size": 10}

        self.database.save_rule(rule, source, [behavior])
        summary = self.database.get_rules()[0]
        saved = self.database.get_rule_by_id(summary["id"])

        self.assertNotIn("content", summary)
        self.assertEqual(saved["content"], rule.content)
        self.assertEqual(saved["behaviors"][0]["name"], "Persistence")

    def test_recent_duplicate_rule_is_not_inserted(self):
        rule = Rule("Example", "content")
        source = {"file_name": "sample.bin", "file_path": "C:/sample.bin", "file_size": 10}
        self.database.save_rule(rule, source)
        self.database.save_rule(rule, source)
        self.assertEqual(len(self.database.get_rules()), 1)

    def test_distinct_rule_after_duplicate_window_is_inserted(self):
        first = Rule("Example", "content")
        second = Rule("Example", "content")
        second.created_at = first.created_at + timedelta(seconds=3)
        source = {"file_name": "sample.bin", "file_path": "C:/sample.bin", "file_size": 10}
        self.database.save_rule(first, source)
        self.database.save_rule(second, source)
        connection = sqlite3.connect(self.db_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 2)

    def test_scan_history_round_trip_and_duplicate_prevention(self):
        rule = Rule("Example", "content")
        source = {"file_name": "source.bin", "file_path": "C:/source.bin", "file_size": 10}
        behavior = BehaviorTag("Network / Downloader", "URL", "Medium", ["https://evil.example"])
        self.database.save_rule(rule, source, [behavior])
        saved_rule = self.database.get_rule_by_id(self.database.get_rules()[0]["id"])
        target = {"file_name": "target.bin", "file_path": "C:/target.bin", "file_size": 20}
        scan = ScanResult(True, ["Example"], "[Example]")

        self.database.save_scan_result(saved_rule, target, scan)
        self.database.save_scan_result(saved_rule, target, scan)
        history = self.database.get_scan_history()

        self.assertEqual(len(history), 1)
        self.assertTrue(history[0]["is_matched"])
        self.assertEqual(history[0]["behaviors"][0]["name"], "Network / Downloader")

    def test_analysis_history_round_trip(self):
        analysis = AnalysisResult(
            {"file_name": "sample.bin", "file_path": "C:/sample.bin", "file_size": 10},
            ["marker"],
            [("marker", 5)],
            Rule("Example", "content"),
            ScanResult(False, [], "[]"),
        )
        self.database.save_analysis(analysis)
        history = self.database.get_history()
        self.assertEqual(history[0]["file_name"], "sample.bin")
        self.assertEqual(history[0]["status"], "Clean")
        self.assertEqual(history[0]["matched_rules"], [])

    def test_invalid_behavior_json_is_tolerated(self):
        self.assertEqual(self.database._behaviors_from_json("not-json"), [])


if __name__ == "__main__":
    unittest.main()
