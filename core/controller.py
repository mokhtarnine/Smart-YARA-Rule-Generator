import os
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
        self.string_extractor = StringExtractor()
        self.filter_engine = FilterEngine()
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
    def get_saved_rules(self):
        """
        Return all saved YARA rules from database.
        """
        return self.database.get_rules()
    
    def get_scan_history(self):
        """
        Return all scan history from databse
        """
        return self.database.get_scan_history()
    
    def generate_and_save_rule(self, source_file_path:str,rule_name: str):
        """
        Generate YARA rule from source file and save it in database.
        """
        # load source file 
        data = self.file_loader.load_file(source_file_path)

        # get source file info
        source_file_info = self.file_loader.get_file_info()

        # Extract strings
        strings = self.string_extractor.extract_all_strings(data)

        #filter suspicious strings
        scored_strings = self.filter_engine.filter_strings(strings)

        # Generate rule using custom rule name
        rule_generator = RuleGenerator(rule_name=rule_name, author="mokhtar")
        rule_content = rule_generator.generate_rule(scored_strings)

        #validate generated rule
        is_valid = self.yara_scanner.validate_rule(rule_content)

        if not is_valid:
            return{
                "success": False,
                "message": "Generated YARA rule is invalid",
                "rule": rule_content
            }
        
        # create Rule model
        rule_model = Rule(
            name = rule_name,
            content = rule_content,
            author="mokhtar",
            description = "Generated from source file"
        )

        # save rule in database
        self.database.save_rule(rule_model, source_file_info)

        # return save rule
        return rule_model
        
    def scan_file_with_saved_rule(self, target_file_path:str, rule_id:int):
        """
        Scan target file suing a saved YARA rule from database.
        """
        # load saved rule from database
        saved_rule = self.database.get_rule_by_id(rule_id)

        if saved_rule is None:
            return{
                "success": False,
                "message": "Rule not found"
            }
        
        rule_content = saved_rule["content"]

        # validate rule before scanning 
        is_valid = self.yara_scanner.validate_rule(rule_content)

        if not is_valid:
            return{
                "success": False,
                "message": "Saved YARA rule is invalid",
                "rule": rule_content
            }
        
        # scan target file
        raw_scan_result = self.yara_scanner.scan(target_file_path, rule_content)

        # convert dictionnary to ScanResult model
        scan_model = ScanResult(
            is_matched = raw_scan_result["is_matched"],
            matched_rules = raw_scan_result["matched_rules"],
            details = raw_scan_result["details"]
        )

        target_file_info = {
            "file_name": os.path.basename(target_file_path),
            "file_path": target_file_path,
            "file_size": os.path.getsize(target_file_path)
        }

        self.database.save_scan_result(saved_rule, target_file_info, scan_model)

        return scan_model