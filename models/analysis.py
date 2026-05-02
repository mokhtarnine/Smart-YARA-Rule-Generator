from datetime import datetime

class AnalysisResult:
    """
    Represents the complete result of analyzing one file.
    """

    def __init__(self,file_info:dict, strings:list,scored_strings:list,rule,scan_result):
        self.file_info = file_info
        self.strings = strings
        self.scored_strings = scored_strings
        self.rule = rule
        self.scan_result = scan_result
        self.analyzed_at = datetime.now()
        
    def total_strings(self) -> int:
        """
        Return number of extracted strings.
        """
        return len(self.strings)

    def top_strings(self,limit: int = 10) -> list:
        """
        return top supicious scored strings.
        """
        return self.scored_strings[:limit]
    def status(self) -> str:
        """
        return final analysis status from scan result.
        """
        return self.scan_result.status()
    def to_dict(self) -> dict:
        """
        convert full analysis result  to dictonary.
        Useful later for database or GUI.
        """
        return{
            "file_info": self.file_info,
            "total_strings":self.total_strings(),
            "top_strings":self.top_strings(),
            "rule": self.rule.to_dict(),
            "scan_result":self.scan_result.to_dict(),
            "status":self.status(),
            "analyzed_at":self.analyzed_at.strftime("%Y-%m-%d %H:%M:%S")
        }