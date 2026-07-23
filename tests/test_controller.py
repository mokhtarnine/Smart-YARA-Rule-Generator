import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from models.scan_result import ScanResult


class ControllerTests(unittest.TestCase):
    def make_controller(self):
        with patch("core.controller.Database") as database_class:
            from core.controller import Controller

            controller = Controller()
        controller.database = database_class.return_value
        return controller

    def test_generate_and_save_rule_orchestrates_pipeline(self):
        controller = self.make_controller()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"https://evil.example cmd.exe /c whoami")
            result = controller.generate_and_save_rule(str(source), "Threat Rule", "Tester")

        self.assertEqual(result["rule"].name, "Threat Rule")
        self.assertIn("rule Threat_Rule", result["rule"].content)
        self.assertTrue(result["behaviors"])
        controller.database.save_rule.assert_called_once()

    def test_generate_does_not_save_invalid_rule(self):
        controller = self.make_controller()
        controller.yara_scanner.validate_rule = MagicMock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"ordinary content")
            result = controller.generate_and_save_rule(str(source), "Rule")

        self.assertFalse(result["success"])
        controller.database.save_rule.assert_not_called()

    def test_scan_returns_error_when_rule_is_missing(self):
        controller = self.make_controller()
        controller.database.get_rule_by_id.return_value = None
        self.assertEqual(
            controller.scan_file_with_saved_rule("target.bin", 99),
            {"success": False, "message": "Rule not found"},
        )

    def test_scan_saved_rule_builds_model_and_saves_result(self):
        controller = self.make_controller()
        saved_rule = {
            "id": 1,
            "name": "Example",
            "content": 'rule Example { condition: true }',
            "behaviors": [],
        }
        controller.database.get_rule_by_id.return_value = saved_rule
        with tempfile.NamedTemporaryFile() as target:
            target.write(b"content")
            target.flush()
            result = controller.scan_file_with_saved_rule(target.name, 1)

        self.assertIsInstance(result, ScanResult)
        self.assertTrue(result.is_matched)
        controller.database.save_scan_result.assert_called_once()

    def test_scan_rejects_invalid_saved_rule(self):
        controller = self.make_controller()
        controller.database.get_rule_by_id.return_value = {
            "id": 1,
            "name": "Broken",
            "content": "rule broken { condition: }",
        }
        result = controller.scan_file_with_saved_rule("target.bin", 1)
        self.assertFalse(result["success"])
        controller.database.save_scan_result.assert_not_called()


if __name__ == "__main__":
    unittest.main()
