from datetime import datetime

class Rule:
    """
    Represents a generated YARA rule
    """
    def __init__(self,name:str, content:str,author:str="Analyst",description:str=""):
        self.name = name
        self.content = content
        self.author = author
        self.description = description
        self.created_at = datetime.now()

    def is_empty(self) -> bool:
        """
        check if the rule content is empty.
        """
        return len(self.content.strip()) == 0
    def to_dict(self) -> dict:
        """
        Convert rule object to dictonary
        Useful later for databse saving or GUI display
        """
        return {
            "name" : self.name,
            "content":self.content,
            "author": self.author,
            "description": self.description,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }