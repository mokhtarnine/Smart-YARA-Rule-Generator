import re

class FilterEngine:
    """
    Filter and score extracted strings for malware ananlysis.
    """
    def __init__(self, min_length:int= 4):
        self.min_length = min_length

        #suspicious keyworks
        self.keyworkds = [
            "http","https","cmd","powershell",
            ".exe",".dll","LoadLibrary","GetProcAddress","VirtualAlloc",
            "CreateFile","WriteFile","HKEY","Software","Run","User-Agent"
        ]
    #**********************Remove noise*************************
    def remove_noise(self, strings:list) -> list:
        """
        Remove useless strings (too short , repetitive, junk)
        """
        cleaned = []
        for s in strings:
            s = s.strip()

            if len(s) < self.min_length:
                continue

            #remove strings with too many repeating chars
            if len(set(s)) <= 2:
                continue

            #remove very nois strings (like random symblols)
            if re.fullmatch(r"[^\w\s]{4,}",s):
                continue

            cleaned.append(s)
        return cleaned
    
#************************ DETECT TYPE *****************************
    def detect_type(self, s:str) -> str:
        """
        Identify the type of string.
        """
        if re.search(r"http[s]?://",s):
            return "url"
        if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", s):
            return "ip"
        if "cmd.exe" in s or "powershell" in s:
            return "command"
        if "HKEY" in s:
            return "registry"
        if s.endswith(".dll"):
            return "dll" 
        if s.endswith(".exe"):
            return "exe"
        if any(api in s for api in ["LoadLibrary","GetProcAddress","VirtualAlloc"]):
            return "api"
        return "other"
    
#************************* SCORING ********************************
    def score_string(self, s: str) -> int:
        """
        Assign a score based on how suspicious the string is.
        """
        score = 0
        #keyword scoring
        for k in self.keyworkds:
            if k.lower() in s.lower():
                score += 5
        #type-based scoring
        t = self.detect_type(s)

        if t == "url":
            score += 10
        elif t == "ip":
            score += 8
        elif t == "command":
            score += 9
        elif t == "registry":
            score += 7
        elif t == "api":
            score += 6
        return score
#**************************** MAIN FILTER **************************
    def filter_strings(self,strings:list) -> list:
        """
        clean, score, and sort strings.
        """
        #step 1 : remove noise
        cleaned = self.remove_noise(strings)
        #step 2 : score each string
        scored = []
        for s in cleaned:
            score = self.score_string(s)
            scored.append((s, score))
        #step 3 : sort by score (high -> low)
        scored.sort(key=lambda x: x[1], reverse=True)

        return scored
#***************************** tor strings ************************
    def get_top_strings(self, scored_strings:list, top_n:int = 10) -> list:
        """
        Return top N most suspicious strings.
        """
        return [s for s, score in scored_strings[:top_n]]