import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path


class Database:
    """
    Handles saving and reading analysis results from SQLite database.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or self._default_db_path()
        self.create_table()

    def _default_db_path(self) -> str:
        app_data_dir = Path(os.getenv("LOCALAPPDATA", Path.home())) / "SmartYaraGenerator"
        app_data_dir.mkdir(parents=True, exist_ok=True)
        return str(app_data_dir / "analysis_history.db")

    def connect(self):
        """
        Create database connection.
        """
        return sqlite3.connect(self.db_path)

    def create_table(self):
        """
        Create tables if they do not exist.
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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT,
                description TEXT,
                source_file_name TEXT,
                source_file_path TEXT,
                source_file_size INTEGER,
                behaviors TEXT,
                created_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                rule_name TEXT,
                target_file_name TEXT,
                target_file_path TEXT,
                target_file_size INTEGER,
                is_matched INTEGER,
                matched_rules TEXT,
                behaviors TEXT,
                details TEXT,
                scanned_at TEXT
            )
        """)

        conn.commit()
        conn.close()

        self._add_column_if_missing("rules", "behaviors", "TEXT")
        self._add_column_if_missing("scan_history", "behaviors", "TEXT")

    def _add_column_if_missing(self, table_name: str, column_name: str, column_type: str):
        """
        Add a column to an existing table if it does not already exist.
        Useful because CREATE TABLE IF NOT EXISTS does not update old tables.
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [column[1] for column in cursor.fetchall()]

        if column_name not in columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            conn.commit()

        conn.close()

    def _behaviors_to_json(self, behaviors: list = None) -> str:
        """
        Convert BehaviorTag objects or behavior dictionaries to JSON text.
        """
        behaviors = behaviors or []
        behavior_data = []

        for behavior in behaviors:
            if hasattr(behavior, "to_dict"):
                behavior_data.append(behavior.to_dict())
            elif isinstance(behavior, dict):
                behavior_data.append(behavior)

        return json.dumps(behavior_data)

    def _behaviors_from_json(self, behaviors_json: str) -> list:
        """
        Convert behavior JSON text back to a Python list.
        """
        if not behaviors_json:
            return []

        try:
            return json.loads(behaviors_json)
        except json.JSONDecodeError:
            return []

    def _first_non_empty_behaviors(self, *behavior_sources) -> list:
        """
        Return the first behavior source that contains at least one behavior.
        """
        for source in behavior_sources:
            behaviors = self._behaviors_from_json(source)

            if behaviors:
                return behaviors

        return []

    def save_rule(self, rule, source_file_info: dict, behaviors: list = None):
        """
        Save generated YARA rule and detected behaviors to database.
        """
        rule_data = rule.to_dict()
        behaviors_json = self._behaviors_to_json(behaviors)
        created_at = rule_data.get("created_at")

        conn = self.connect()
        cursor = conn.cursor()

        if self._is_recent_duplicate_rule(
            cursor=cursor,
            name=rule_data.get("name"),
            content=rule_data.get("content"),
            author=rule_data.get("author"),
            source_file_path=source_file_info.get("file_path"),
            created_at=created_at
        ):
            conn.close()
            return

        cursor.execute("""
            INSERT INTO rules (
                name,
                content,
                author,
                description,
                source_file_name,
                source_file_path,
                source_file_size,
                behaviors,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_data.get("name"),
            rule_data.get("content"),
            rule_data.get("author"),
            rule_data.get("description"),
            source_file_info.get("file_name"),
            source_file_info.get("file_path"),
            source_file_info.get("file_size"),
            behaviors_json,
            created_at
        ))

        conn.commit()
        conn.close()

    def _is_recent_duplicate_rule(
        self,
        cursor,
        name,
        content,
        author,
        source_file_path,
        created_at
    ) -> bool:
        """
        Avoid saving the same generated rule multiple times from repeated clicks.
        """
        cursor.execute("""
            SELECT created_at
            FROM rules
            WHERE name = ?
              AND content = ?
              AND author = ?
              AND source_file_path = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            name,
            content,
            author,
            source_file_path
        ))

        row = cursor.fetchone()

        if row is None:
            return False

        try:
            previous_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            current_time = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return row[0] == created_at

        return abs((current_time - previous_time).total_seconds()) <= 2

    def get_rules(self):
        """
        Return all saved YARA rules.
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                name,
                author,
                description,
                source_file_name,
                source_file_path,
                source_file_size,
                behaviors,
                created_at
            FROM rules
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        rules = []

        for row in rows:
            rules.append({
                "id": row[0],
                "name": row[1],
                "author": row[2],
                "description": row[3],
                "source_file_name": row[4],
                "source_file_path": row[5],
                "source_file_size": row[6],
                "behaviors": self._behaviors_from_json(row[7]),
                "created_at": row[8]
            })

        return self._unique_rules(rules)

    def _unique_rules(self, rules: list) -> list:
        """
        Hide duplicated saved rules that represent the same generated rule.
        """
        unique_rules = []
        seen_keys = set()

        for rule in rules:
            key = (
                rule.get("name"),
                rule.get("author"),
                rule.get("source_file_path"),
                tuple(behavior.get("name") for behavior in rule.get("behaviors", []))
            )

            if key in seen_keys:
                continue

            seen_keys.add(key)
            unique_rules.append(rule)

        return unique_rules

    def get_rule_by_id(self, rule_id: int):
        """
        Return one saved rule by id, including full rule content and behaviors.
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                name,
                content,
                author,
                description,
                source_file_name,
                source_file_path,
                source_file_size,
                behaviors,
                created_at
            FROM rules
            WHERE id = ?
        """, (rule_id,))

        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        return {
            "id": row[0],
            "name": row[1],
            "content": row[2],
            "author": row[3],
            "description": row[4],
            "source_file_name": row[5],
            "source_file_path": row[6],
            "source_file_size": row[7],
            "behaviors": self._behaviors_from_json(row[8]),
            "created_at": row[9]
        }

    def save_analysis(self, analysis_result):
        """
        Save AnalysisResult object to database.
        """
        data = analysis_result.to_dict()

        file_info = data["file_info"]
        scan_result = data["scan_result"]
        rule = data["rule"]

        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO analysis_results (
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "file_name": row[1],
                "file_path": row[2],
                "file_size": row[3],
                "status": row[4],
                "matched_rules": json.loads(row[5]) if row[5] else [],
                "rule_name": row[6],
                "details": row[7],
                "analyzed_at": row[8]
            })

        return history

    def save_scan_result(self, saved_rule: dict, target_file_info: dict, scan_result):
        """
        Save result of scanning a target file with a saved rule.
        """
        scan_data = scan_result.to_dict()
        behaviors_json = self._behaviors_to_json(saved_rule.get("behaviors", []))
        is_matched = 1 if scan_result.is_matched else 0
        matched_rules_json = json.dumps(scan_data.get("matched_rules", []))
        scanned_at = scan_data.get("scanned_at")

        conn = self.connect()
        cursor = conn.cursor()

        if self._is_recent_duplicate_scan(
            cursor=cursor,
            rule_id=saved_rule.get("id"),
            target_file_path=target_file_info.get("file_path"),
            is_matched=is_matched,
            matched_rules_json=matched_rules_json,
            details=scan_data.get("details"),
            scanned_at=scanned_at
        ):
            conn.close()
            return

        cursor.execute("""
            INSERT INTO scan_history (
                rule_id,
                rule_name,
                target_file_name,
                target_file_path,
                target_file_size,
                is_matched,
                matched_rules,
                behaviors,
                details,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            saved_rule.get("id"),
            saved_rule.get("name"),
            target_file_info.get("file_name"),
            target_file_info.get("file_path"),
            target_file_info.get("file_size"),
            is_matched,
            matched_rules_json,
            behaviors_json,
            scan_data.get("details"),
            scanned_at
        ))

        conn.commit()
        conn.close()

    def _is_recent_duplicate_scan(
        self,
        cursor,
        rule_id,
        target_file_path,
        is_matched,
        matched_rules_json,
        details,
        scanned_at
    ) -> bool:
        """
        Avoid saving the same scan twice when the scan button is triggered twice quickly.
        """
        cursor.execute("""
            SELECT scanned_at
            FROM scan_history
            WHERE rule_id = ?
              AND target_file_path = ?
              AND is_matched = ?
              AND matched_rules = ?
              AND details = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            rule_id,
            target_file_path,
            is_matched,
            matched_rules_json,
            details
        ))

        row = cursor.fetchone()

        if row is None:
            return False

        try:
            previous_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            current_time = datetime.strptime(scanned_at, "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return row[0] == scanned_at

        return abs((current_time - previous_time).total_seconds()) <= 2

    def get_scan_history(self):
        """
        Return saved scan history.
        """
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                scan_history.id,
                scan_history.rule_id,
                scan_history.rule_name,
                scan_history.target_file_name,
                scan_history.target_file_path,
                scan_history.target_file_size,
                scan_history.is_matched,
                scan_history.matched_rules,
                scan_history.behaviors,
                scan_history.details,
                scan_history.scanned_at,
                rules.behaviors
            FROM scan_history
            LEFT JOIN rules ON scan_history.rule_id = rules.id
            ORDER BY scan_history.id DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        history = []

        for row in rows:
            history.append({
                "id": row[0],
                "rule_id": row[1],
                "rule_name": row[2],
                "target_file_name": row[3],
                "target_file_path": row[4],
                "target_file_size": row[5],
                "is_matched": bool(row[6]),
                "matched_rules": json.loads(row[7]) if row[7] else [],
                "behaviors": self._first_non_empty_behaviors(row[8], row[11]),
                "details": row[9],
                "scanned_at": row[10]
            })

        return self._unique_scan_history(history)

    def _unique_scan_history(self, history: list) -> list:
        """
        Hide duplicated scan rows that represent the same analysis result.
        """
        unique_history = []
        seen_keys = set()

        for item in history:
            key = (
                item.get("rule_id"),
                item.get("target_file_path"),
                item.get("is_matched"),
                tuple(item.get("matched_rules", [])),
                item.get("details")
            )

            if key in seen_keys:
                continue

            seen_keys.add(key)
            unique_history.append(item)

        return unique_history
