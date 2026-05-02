from datetime import datetime 

class ScanResult:
    """
    Represents the result of scanning  a file with YARA.
    """

    def __init__(self, is_matched: bool, matched_rules: list, details: str):
        self.is_matched = is_matched
        self.matched_rules = matched_rules
        self.details = details
        self.scanned_at = datetime.now()


    def status(self)-> str:
        """
        Return readable scan status.
        """
        if self.is_matched:
            return "Malicious /Suspicious"
        return "Clean"

    def has_matches(self) -> bool:
        """
        check if any YARA rule mathced
        """
        return len(self.matched_rules) > 0
    def to_dict(self)-> dict:
        """
        Convert scan result object to dictinary.
        Useful later for GUI or database.
        """
        return{
            "is_matched": self.is_matched,
            "matched_rules":self.matched_rules,
            "details":self.details,
            "status": self.status(),
            "scanned_at":self.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    