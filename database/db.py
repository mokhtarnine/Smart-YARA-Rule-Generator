import sqlite3
import json
from datetime import datetime

class Database:
    """
    Handles saving and reading analysis results from SQLite databse,
    """
    def __init__(self,db_path:str = "analysis_history.db"):
        self.db_path = db_path
        self.create_table()

    def connect(self):
        """
        create database connection
        """
        return sqlite3.connect(self.db_path)
    def create_table(self):
        """
        create analysis table if it does not exist .
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       file_name TEXT,
                       file_path TEXT,
                       file_size INTEGER,
                       status TEXT,
                       matched_rules TEXT,
                       rule_name TEXT,
                       rule_content TEXT,
                       details TEXT,
                       analyzed_at TEXT
                       )
        """)
        conn.commit()
        conn.close()

    def save_analysis(self, analysis_result):
        """
        save analysisResutl object to database.
        """
        data = analysis_result.to_dict()

        file_info = data["file_info"]
        scan_result = data["scan_result"]
        rule = data["rule"]

        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO analysis_results(
                    file_name,
                    file_path,
                    file_size,
                    status,
                    matched_rules,
                    rule_name,
                    rule_content,
                    details,
                    analyzed_at
            )
            VALUES (?, ?, ?, ?, ?, ? , ?, ?, ?)
        """, (
            file_info.get("file_name"),
            file_info.get("file_path"),
            file_info.get("file_size"),
            data["status"],
            json.dumps(scan_result.get("matched_rules", [])),
            rule.get("name"),
            rule.get("content"),
            scan_result.get("details"),
            data["analyzed_at"]
        ))

        conn.commit()
        conn.close()

    def get_history(self):
        """
        Return all saved analysis results.
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                file_name,
                file_path,
                file_size,
                status,
                matched_rules,
                rule_name,
                details,
                analyzed_at
            FROM analysis_results
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        history = []

        for row in rows:
            history.append({
                "id": row[0],
                "file_name":row[1],
                "file_path":row[2],
                "file_size":row[3],
                "status":row[4],
                "matched_rules":json.loads(row[5]) if row[5] else [],
                "rule_name":row[6],
                "details":row[7],
                "analyzed_at":row[8]
            })
        return history



