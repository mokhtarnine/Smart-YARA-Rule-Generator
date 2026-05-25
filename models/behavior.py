class BehaviorTag:
    """
    Represents one detected malware behavior
    """

    def __init__(self, name: str, reason: str, severity:str, indicators: list):
        self.name = name
        self.reason = reason
        self.severity = severity
        self.indicators = indicators

    def to_dict(self) -> dict:
        """
        convert behavior object to dictoinary.
        useful later for GUI or database
        """
        return {
            "name": self.name,
            "reason": self.reason,
            "severity":self.severity,
            "indicators":self.indicators
        }
    
    def summary(self) -> str:
        """
        Return short readable behavior summary.
        """
        return f"{self.name} ({self.severity})"
    
    def has_indicators(self) -> bool:
        """
        check if this behavior has matched indicators.
        """
        return len(self.indicators) > 0