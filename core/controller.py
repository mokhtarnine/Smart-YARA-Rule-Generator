from core.file_loader import FileLoader
from core.string_extractor import StringExtractor
from core.filter_engine import FilterEngine
from core.rule_generator import RuleGenerator
from core.yara_scanner import YaraScanner

from models.rule import Rule
from models.scan_result import ScanResult
from models.analysis import AnalysisResult

from database.db import Database



class Controller:
    """
    Main coordinator of the application.
    It connects all core components together.
    """
    def __init__(self):
        self.file_loader = FileLoader()
        self.string_extractor = StringExtractor(min_length=3)
        self.filter_engine = FilterEngine(min_length=3)
        self.rule_generator = RuleGenerator()
        self.yara_scanner = YaraScanner()
        self.database = Database()

    def analyze_file(self, file_path: str) :
        # load file
        data = self.file_loader.load_file(file_path)

        # extract strings 
        strings = self.string_extractor.extract_all_strings(data)

        # filter suspicious strings
        scored_strings = self.filter_engine.filter_strings(strings)

        # Generate YARA rule
        rule = self.rule_generator.generate_rule(scored_strings)

        # valide rule
        is_valid = self.yara_scanner.validate_rule(rule)

        if not is_valid:
            return {
                "success": False,
                "message": "Generated YARA rule is invalid",
                "rule": rule
            }
        # scan file
        scan_result = self.yara_scanner.scan(file_path,rule)
        # used model rule for implement dipslay content rule
        rule_model = Rule(
            name = self.rule_generator.rule_name,
            content= rule,
            author = self.rule_generator.author,
            description= "Generated from extracted suspicious strings"
        )
        # used model scan to display content scanResult
        scan_model = ScanResult(
            is_matched= scan_result["is_matched"],
            matched_rules= scan_result["matched_rules"],
            details= scan_result["details"]
        )
        # used model analysis result 
        analysis_result = AnalysisResult(
            file_info= self.file_loader.get_file_info(),
            strings=strings,
            scored_strings= scored_strings,
            rule = rule_model,
            scan_result=scan_model
        )
        self.database.save_analysis(analysis_result)

        #Return final result
        return analysis_result
        