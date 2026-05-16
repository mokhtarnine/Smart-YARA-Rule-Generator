from PySide6.QtCore import Qt
from pathlib import Path

from PySide6.QtGui import QPixmap, QPalette, QBrush, QIcon
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QHeaderView,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import Controller


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ICONS_DIR = PROJECT_ROOT / "assets" / "icons"


class MainWindow(QMainWindow):
    """
    Main desktop window for the Smart YARA Rule Generator.
    """

    def __init__(self):
        super().__init__()

        self.controller = Controller()

        self.setWindowTitle("Smart YARA Rule Generator")
        self.resize(1000, 650)

        self.tabs = QTabWidget()
        self.tabs.tabBar().setExpanding(True)
        self.tabs.tabBar().setUsesScrollButtons(False)
        self.tabs.addTab(self._generate_rule_tab(), self._icon("generate.svg"), "Generate Rule")
        self.tabs.addTab(self._scan_file_tab(), self._icon("scan.svg"), "Scan File")
        self.tabs.addTab(self._saved_rules_tab(), self._icon("rules.svg"), "Saved Rules")
        self.tabs.addTab(self._history_tab(), self._icon("history.svg"), "History")
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                min-width: 240px;
                padding: 10px 16px;
                font-size: 13px;
            }
        """)

        self.setCentralWidget(self.tabs)
        self._apply_dark_style()

    def _icon(self, name: str) -> QIcon:
        return QIcon(str(ICONS_DIR / name))

    def _apply_dark_style(self):
        background_path = "C:/Users/mokht/OneDrive/Desktop/PFE/yara/assets/images/Intro.jfif"
        pixmap = QPixmap(background_path)

        if not pixmap.isNull():
            palette = QPalette()
            palette.setBrush(QPalette.Window, QBrush(pixmap))
            self.setPalette(palette)
            self.setAutoFillBackground(True)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #050608;
            }

            QTabWidget {
                border-image: url("C:/Users/mokht/OneDrive/Desktop/PFE/yara/assets/images/Intro.jfif") 0 0 0 0 stretch stretch;
            }

            QTabWidget::pane {
                border: 1px solid #26323a;
                background: rgba(5, 8, 10, 210);
            }

            QTabBar::tab {
                min-width: 240px;
                padding: 10px 16px;
                font-size: 13px;
                color: #c7d5df;
                background: #111820;
                border: 1px solid #26323a;
            }

            QTabBar::tab:selected {
                color: #ffffff;
                background: #19323a;
                border-bottom: 2px solid #38c7b7;
            }

            QWidget {
                color: #e8eef2;
                font-size: 13px;
            }

            QLabel {
                color: #e8eef2;
            }

            QLineEdit, QTextEdit, QComboBox, QTableWidget {
                color: #f2f7fa;
                background: rgba(10, 15, 19, 230);
                border: 1px solid #30404a;
                border-radius: 4px;
                padding: 6px;
                selection-background-color: #1f7a72;
            }

            QTextEdit#rulePreview, QTextEdit#scanPreview {
                color: #f6fbff;
                border: 1px solid #33515a;
                border-radius: 4px;
                border-image: url("C:/Users/mokht/OneDrive/Desktop/PFE/yara/assets/images/code_panel_background.png") 0 0 0 0 stretch stretch;
                padding: 10px;
                font-family: Consolas, "Courier New", monospace;
                font-size: 13px;
                selection-background-color: #1f7a72;
            }

            QPushButton {
                color: #ffffff;
                background: #176b63;
                border: 1px solid #2aa89d;
                border-radius: 4px;
                padding: 8px 14px;
            }

            QPushButton:hover {
                background: #1e8178;
            }

            QPushButton:pressed {
                background: #11524d;
            }

            QHeaderView::section {
                color: #ffffff;
                background: #14232b;
                border: 1px solid #30404a;
                padding: 6px;
            }
        """)

    def _placeholder_tab(self, text: str) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)

        layout.addWidget(label)
        return tab

    def _generate_rule_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        source_label = QLabel("Source file")
        self.source_file_input = QLineEdit()
        self.source_file_input.setPlaceholderText("Choose File A")

        browse_button = QPushButton("Browse")
        browse_button.setIcon(self._icon("folder.svg"))
        browse_button.clicked.connect(self._choose_source_file)

        source_layout = QHBoxLayout()
        source_layout.addWidget(self.source_file_input)
        source_layout.addWidget(browse_button)

        rule_name_label = QLabel("Rule name")
        self.rule_name_input = QLineEdit()
        self.rule_name_input.setPlaceholderText("Example: MySavedRule")

        generate_button = QPushButton("Generate and Save")
        generate_button.setIcon(self._icon("generate.svg"))
        generate_button.clicked.connect(self._generate_and_save_rule)

        clear_generate_button = QPushButton("New Rule")
        clear_generate_button.setIcon(self._icon("refresh.svg"))
        clear_generate_button.clicked.connect(self._clear_generate_rule_form)

        generate_actions_layout = QHBoxLayout()
        generate_actions_layout.addWidget(generate_button)
        generate_actions_layout.addWidget(clear_generate_button)

        self.generate_status_label = QLabel("")
        self.generate_status_label.setWordWrap(True)

        self.generated_rule_preview = QTextEdit()
        self.generated_rule_preview.setObjectName("rulePreview")
        self.generated_rule_preview.setReadOnly(True)
        self.generated_rule_preview.setPlaceholderText("Generated YARA rule will appear here.")

        layout.addWidget(source_label)
        layout.addLayout(source_layout)
        layout.addWidget(rule_name_label)
        layout.addWidget(self.rule_name_input)
        layout.addLayout(generate_actions_layout)
        layout.addWidget(self.generate_status_label)
        layout.addWidget(self.generated_rule_preview, 1)

        return tab

    def _scan_file_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        rule_label = QLabel("Saved rule")
        self.saved_rules_combo = QComboBox()

        refresh_button = QPushButton("Refresh Rules")
        refresh_button.setIcon(self._icon("refresh.svg"))
        refresh_button.clicked.connect(self._load_saved_rules)

        rule_layout = QHBoxLayout()
        rule_layout.addWidget(self.saved_rules_combo, 1)
        rule_layout.addWidget(refresh_button)

        target_label = QLabel("Target file")
        self.target_file_input = QLineEdit()
        self.target_file_input.setPlaceholderText("Choose File B")

        browse_button = QPushButton("Browse")
        browse_button.setIcon(self._icon("folder.svg"))
        browse_button.clicked.connect(self._choose_target_file)

        target_layout = QHBoxLayout()
        target_layout.addWidget(self.target_file_input)
        target_layout.addWidget(browse_button)

        scan_button = QPushButton("Scan File")
        scan_button.setIcon(self._icon("play.svg"))
        scan_button.clicked.connect(self._scan_file_with_saved_rule)

        clear_scan_button = QPushButton("New Scan")
        clear_scan_button.setIcon(self._icon("refresh.svg"))
        clear_scan_button.clicked.connect(self._clear_scan_file_form)

        scan_actions_layout = QHBoxLayout()
        scan_actions_layout.addWidget(scan_button)
        scan_actions_layout.addWidget(clear_scan_button)

        self.scan_status_label = QLabel("")
        self.scan_status_label.setWordWrap(True)

        self.scan_details_preview = QTextEdit()
        self.scan_details_preview.setObjectName("scanPreview")
        self.scan_details_preview.setReadOnly(True)
        self.scan_details_preview.setPlaceholderText("Scan details will appear here.")

        layout.addWidget(rule_label)
        layout.addLayout(rule_layout)
        layout.addWidget(target_label)
        layout.addLayout(target_layout)
        layout.addLayout(scan_actions_layout)
        layout.addWidget(self.scan_status_label)
        layout.addWidget(self.scan_details_preview, 1)

        self._load_saved_rules()

        return tab

    def _saved_rules_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        refresh_button = QPushButton("Refresh Saved Rules")
        refresh_button.setIcon(self._icon("refresh.svg"))
        refresh_button.clicked.connect(self._load_saved_rules_table)
        refresh_button.setFixedWidth(200)

        self.saved_rules_table = QTableWidget()
        self.saved_rules_table.setColumnCount(5)
        self.saved_rules_table.setHorizontalHeaderLabels([
            "ID",
            "Name",
            "Author",
            "Source File",
            "Created At",
        ])
        self.saved_rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.saved_rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.saved_rules_table.setAlternatingRowColors(True)
        self.saved_rules_table.verticalHeader().setVisible(False)
        self.saved_rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.saved_rules_table.horizontalHeader().setMinimumSectionSize(110)

        layout.addWidget(self.saved_rules_table, 1)

        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        actions_layout.addWidget(refresh_button)
        actions_layout.addStretch()

        layout.addLayout(actions_layout)

        self._load_saved_rules_table()

        return tab

    def _history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "ID",
            "Rule",
            "Target File",
            "Matched",
            "Matched Rules",
            "Scanned At",
        ])
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.horizontalHeader().setMinimumSectionSize(100)

        refresh_button = QPushButton("Refresh History")
        refresh_button.setIcon(self._icon("refresh.svg"))
        refresh_button.clicked.connect(self._load_history_table)
        refresh_button.setFixedWidth(160)

        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        actions_layout.addWidget(refresh_button)
        actions_layout.addStretch()

        layout.addWidget(self.history_table, 1)
        layout.addLayout(actions_layout)

        self._load_history_table()

        return tab

    def _choose_source_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose source file")
        if file_path:
            self.source_file_input.setText(file_path)

    def _generate_and_save_rule(self):
        source_file = self.source_file_input.text().strip()
        rule_name = self.rule_name_input.text().strip()

        if not source_file:
            QMessageBox.warning(self, "Missing source file", "Please choose a source file.")
            return

        if not rule_name:
            QMessageBox.warning(self, "Missing rule name", "Please enter a rule name.")
            return

        try:
            result = self.controller.generate_and_save_rule(source_file, rule_name)

            if isinstance(result, dict) and result.get("success") is False:
                self.generate_status_label.setText(f"Error: {result['message']}")
                self.generated_rule_preview.setPlainText(result.get("rule", ""))
                return

            self.generate_status_label.setText(f"Rule saved: {result.name}")
            self.generated_rule_preview.setPlainText(result.content)

        except Exception as e:
            self.generate_status_label.setText(f"Error: {e}")

    def _clear_generate_rule_form(self):
        self.source_file_input.clear()
        self.rule_name_input.clear()
        self.generate_status_label.clear()
        self.generated_rule_preview.clear()

    def _load_saved_rules(self):
        self.saved_rules_combo.clear()

        try:
            rules = self.controller.get_saved_rules()
        except Exception as e:
            self.scan_status_label.setText(f"Error loading rules: {e}")
            return

        for rule in rules:
            label = f'{rule["id"]} - {rule["name"]} ({rule["source_file_name"]})'
            self.saved_rules_combo.addItem(label, rule["id"])

    def _load_saved_rules_table(self):
        try:
            rules = self.controller.get_saved_rules()
        except Exception as e:
            QMessageBox.warning(self, "Error loading rules", str(e))
            return

        self.saved_rules_table.setRowCount(len(rules))

        for row, rule in enumerate(rules):
            values = [
                rule.get("id"),
                rule.get("name"),
                rule.get("author"),
                rule.get("source_file_name"),
                rule.get("created_at"),
            ]

            for column, value in enumerate(values):
                self.saved_rules_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _load_history_table(self):
        try:
            history = self.controller.get_scan_history()
        except Exception as e:
            QMessageBox.warning(self, "Error loading history", str(e))
            return

        self.history_table.setRowCount(len(history))

        for row, item in enumerate(history):
            values = [
                item.get("id"),
                item.get("rule_name"),
                item.get("target_file_name"),
                "Yes" if item.get("is_matched") else "No",
                ", ".join(item.get("matched_rules", [])),
                item.get("scanned_at"),
            ]

            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(str(value)))


    def _choose_target_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose target file")
        if file_path:
            self.target_file_input.setText(file_path)

    def _scan_file_with_saved_rule(self):
        if self.saved_rules_combo.count() == 0:
            QMessageBox.warning(self, "No saved rules", "Generate and save a rule first.")
            return

        target_file = self.target_file_input.text().strip()
        if not target_file:
            QMessageBox.warning(self, "Missing target file", "Please choose a target file.")
            return

        rule_id = self.saved_rules_combo.currentData()

        try:
            result = self.controller.scan_file_with_saved_rule(target_file, rule_id)

            if isinstance(result, dict) and result.get("success") is False:
                self.scan_status_label.setText(f"Error: {result['message']}")
                self.scan_details_preview.clear()
                return

            self.scan_status_label.setText(f"Status: {result.status()}")
            self.scan_details_preview.setPlainText(
                f"Matched: {result.is_matched}\n"
                f"Matched rules: {result.matched_rules}\n"
                f"Details: {result.details}"
            )

        except Exception as e:
            self.scan_status_label.setText(f"Error: {e}")

    def _clear_scan_file_form(self):
        self.target_file_input.clear()
        self.scan_status_label.clear()
        self.scan_details_preview.clear()
