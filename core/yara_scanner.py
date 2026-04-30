import yara

class YaraScanner:
    """
    Responsible for validating YARA rules and scanning files using the YARA engine .
    """
    def __init__(self):
        self.rules = None

    def validate_rule(self, rule: str) -> bool:
        try:
            yara.compile(source=rule)
            return True
        except yara.SyntaxError:
            return False
        
    def scan(self, file_path: str, rule: str) -> dict:
        try:
            compiled_rule = yara.compile(source=rule)
            self.rules = rule

            matches = compiled_rule.match(file_path)

            return {
                "is_matched": len(matches) > 0,
                "matched_rules": [match.rule for match in matches],
                "details": str(matches)
            }
        except yara.SyntaxError as e:
            return {
                "is_matched": False,
                "matched_rules": [],
                "details": f"Invalid YARA rule: {str(e)}"
            }
        
        except Exception as e:
            return {
                "is_matched": False,
                "matched_rules": [],
                "details": f"Scan error: {str(e)}"
            }

