from models.behavior import BehaviorTag

class BehaviorTagger:
    """
    Detect malware Behavior categories from extract/scored strings.
    """
    def __init__(self):
        self.behavior_rules = [
            {
                "name": "Presistence",
                "reason": "Registry Run key or startup indicator found",
                "severity" : "High",
                "keywords": [
                    "hkey",
                    "currentversion\\run",
                    "software\\microsoft\\windows\\currentversion\\run",
                    "startup"
                ]
            },
            {
                "name": "Network / Downloader",
                "reason": "Network URL, domain, or User-Agent indicator found",
                "severity": "Medium",
                "keywords": [
                    "http://",
                    "https://",
                    "user-agent",
                    ".com",
                    ".net",
                    ".org",
                    "download"
                ]
            },
            {
                "name": "Command execution",
                "reason": "Command interpreter or shell execution indicator found",
                "severity": "High",
                "keywords": [
                    "cmd.exe",
                    "powershell",
                    "wscript",
                    "cscript",
                    " /c ",
                    " /k "
                ]
            },
            {
                "name": "Injection / Runtime loading",
                "reason": "Runtime memory allocation or API loading indicator found",
                "severity": "High",
                "keywords": [
                    "virtualalloc",
                    "virtualprotect",
                    "getprocaddress",
                    "loadlibrary",
                    "createremotethread",
                    "writeprocessmemory"
                ]
            },
            {
                "name": "File manipulation",
                "reason": "File creation, writing, or deletion indicator found",
                "severity": "Medium",
                "keywords": [
                    "createfile",
                    "writefile",
                    "deletefile",
                    "copyfile",
                    "movefile"
                ]
            },
            {
                "name": "Anti-analysis suspicion",
                "reason": "Debugger, sandbox, or virtual machine indicator found",
                "severity": "Medium",
                "keywords": [
                    "isdebuggerpresent",
                    "checkremotedebuggerpresent",
                    "sandbox",
                    "vmware",
                    "virtualbox",
                    "vbox",
                    "wireshark",
                    "process explorer"
                ]
            }
        ]
    def detect(self, scored_strings:list) -> list:
        """
        Detect behavior tags from scored strings.

        scored_strings format:
        [
            ("cmd.exe /c whoami", 14),
            ("http://example.com/file.exe", 15)
        ]

        return format:
        [
            {
                "name": "Command execution",
                "reason": "Command interpreter or shell execution indicator found",
                "severity": "High",
                "indicators": ["cmd.exe /c whoami"]
            }
        ]
        """

        behaviors = []

        for rule in self.behavior_rules:
            indicators = self._find_indicators(scored_strings, rule["keywords"])

            if indicators:
                behaviors.append(
                    BehaviorTag(
                        name = rule["name"],
                        reason= rule["reason"],
                        severity= rule["severity"],
                        indicators=indicators
                    )
                )
        return behaviors
    
    def _find_indicators(self, scored_strings: list, keywords: list) -> list:
        """
        find strings that match one behavior rule.
        """

        indicators = []

        for item in scored_strings:
            string_value = self._get_string_value(item)
            string_lower = string_value.lower()

            for keyword in keywords:
                if keyword in string_lower:
                    indicators.append(string_value)
                    break

            return self._unique(indicators)
        

    def _get_string_value(self, item) -> str:
        """
        Accept both:
        - scored tuple: ("text", score)
        - normal string: "text"
        """
        if isinstance(item, tuple):
            return item[0]
        return item
    
    def _unique(self, items: list):
        """
        Remove duplicate indicators while keeping order.
        """
        unique_items = []

        for item in items:
            if item not in unique_items:
                unique_items.append(item)

        return unique_items
    
