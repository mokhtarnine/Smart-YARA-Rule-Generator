from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QRectF
from pathlib import Path

from PySide6.QtGui import QIcon, QPainterPath, QRegion
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QHeaderView,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import Controller
from gui.styles.app_style import build_main_stylesheet


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ICONS_DIR = PROJECT_ROOT / "assets" / "icons"
IMAGES_DIR = PROJECT_ROOT / "assets" / "images"


class MainWindow(QMainWindow):
    """
    Main desktop window for the Smart YARA Rule Generator.
    """

    def __init__(self):
        super().__init__()

        self.controller = Controller()

        self.setWindowTitle("Smart YARA Rule Generator")
        self.resize(1000, 650)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._drag_position = None
        self._window_radius = 24
        self.author_name = "mokhtar"

        self.tabs = QTabWidget()
        self.tabs.tabBar().setExpanding(True)
        self.tabs.tabBar().setUsesScrollButtons(False)
        self.tabs.addTab(self._generate_rule_tab(), self._icon("generate.svg"), "Generate Rule")
        self.tabs.addTab(self._scan_file_tab(), self._icon("scan.svg"), "Scan File")
        self.tabs.addTab(self._saved_rules_tab(), self._icon("rules.svg"), "Saved Rules")
        self.tabs.addTab(self._history_tab(), self._icon("history.svg"), "History")

        self.window_frame = QWidget()
        self.window_frame.setObjectName("windowFrame")

        self.pages = QStackedWidget()
        self.pages.addWidget(self._splash_screen())
        self.pages.addWidget(self.tabs)

        frame_layout = QVBoxLayout(self.window_frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)
        frame_layout.addWidget(self._title_bar())
        frame_layout.addWidget(self.pages, 1)

        self.setCentralWidget(self.window_frame)
        self._apply_dark_style()

    def _icon(self, name: str) -> QIcon:
        return QIcon(str(ICONS_DIR / name))

    def _title_bar(self) -> QWidget:
        title_bar = QWidget()
        title_bar.setObjectName("titleBar")
        title_bar.setFixedHeight(46)
        title_bar.mousePressEvent = self._start_window_drag
        title_bar.mouseMoveEvent = self._move_window
        title_bar.mouseReleaseEvent = self._end_window_drag

        title_label = QLabel("Smart YARA Rule Generator")
        title_label.setObjectName("titleLabel")
        title_label.setAlignment(Qt.AlignCenter)

        minimize_button = QPushButton("-")
        minimize_button.setObjectName("windowButton")
        minimize_button.setFixedSize(34, 30)
        minimize_button.clicked.connect(self.showMinimized)

        self.maximize_button = QPushButton("□")
        self.maximize_button.setObjectName("windowButton")
        self.maximize_button.setFixedSize(34, 30)
        self.maximize_button.clicked.connect(self._toggle_window_size)

        close_button = QPushButton("×")
        close_button.setObjectName("closeButton")
        close_button.setFixedSize(34, 30)
        close_button.clicked.connect(self.close)

        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.setSpacing(6)
        buttons_layout.addWidget(minimize_button)
        buttons_layout.addWidget(self.maximize_button)
        buttons_layout.addWidget(close_button)

        layout = QGridLayout(title_bar)
        layout.setContentsMargins(24, 8, 18, 8)
        layout.setColumnStretch(0, 1)
        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(2, 1)
        layout.addWidget(title_label, 0, 0, 1, 3)
        layout.addLayout(buttons_layout, 0, 2, Qt.AlignRight)

        return title_bar

    def _start_window_drag(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def _move_window(self, event):
        if self._drag_position is not None and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

    def _end_window_drag(self, event):
        self._drag_position = None
        event.accept()

    def _toggle_window_size(self):
        if self.isMaximized():
            self.showNormal()
            self.maximize_button.setText("□")
        else:
            self.showMaximized()
            self.maximize_button.setText("❐")
        self._apply_window_mask()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_window_mask()

    def _apply_window_mask(self):
        if self.isMaximized():
            self.clearMask()
            return

        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), self._window_radius, self._window_radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _apply_dark_style(self):
        background_path = str(IMAGES_DIR / "Intro.jfif").replace("\\", "/")
        panel_background_path = str(IMAGES_DIR / "code_panel_background.png").replace("\\", "/")

        self.setStyleSheet(build_main_stylesheet(background_path, panel_background_path))

    def _splash_screen(self) -> QWidget:
        splash = QWidget()
        splash.setObjectName("splashScreen")

        layout = QVBoxLayout(splash)
        layout.setContentsMargins(90, 70, 90, 70)
        layout.setSpacing(18)

        layout.addStretch()

        app_name = QLabel("Smart YARA\nRule Generator")
        app_name.setObjectName("splashTitle")
        app_name.setAlignment(Qt.AlignCenter)

        title_effect = QGraphicsOpacityEffect(app_name)
        app_name.setGraphicsEffect(title_effect)
        self.splash_animation = QPropertyAnimation(title_effect, b"opacity")
        self.splash_animation.setDuration(2200)
        self.splash_animation.setLoopCount(-1)
        self.splash_animation.setStartValue(0.62)
        self.splash_animation.setKeyValueAt(0.5, 1.0)
        self.splash_animation.setEndValue(0.62)
        self.splash_animation.setEasingCurve(QEasingCurve.InOutSine)
        self.splash_animation.start()

        subtitle = QLabel("Generate, save, and test YARA rules from suspicious files")
        subtitle.setObjectName("splashSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)

        author_label = QLabel("Author name")
        author_label.setObjectName("splashInputLabel")
        author_label.setAlignment(Qt.AlignCenter)

        self.author_input = QLineEdit()
        self.author_input.setObjectName("authorInput")
        self.author_input.setPlaceholderText("Enter author name")
        self.author_input.setText(self.author_name)
        self.author_input.setAlignment(Qt.AlignCenter)
        self.author_input.setFixedWidth(360)
        self.author_input.returnPressed.connect(self._start_app)

        start_button = QPushButton("Start")
        start_button.setObjectName("startButton")
        start_button.setFixedWidth(180)
        start_button.clicked.connect(self._start_app)

        start_layout = QHBoxLayout()
        start_layout.addStretch()
        start_layout.addWidget(start_button)
        start_layout.addStretch()

        layout.addWidget(app_name)
        layout.addWidget(subtitle)
        layout.addSpacing(28)
        layout.addWidget(author_label)
        layout.addWidget(self.author_input, 0, Qt.AlignCenter)
        layout.addLayout(start_layout)
        layout.addStretch()

        return splash

    def _start_app(self):
        author = self.author_input.text().strip()

        if not author:
            QMessageBox.warning(self, "Missing author", "Please enter the author name.")
            return

        self.author_name = author
        self.pages.setCurrentWidget(self.tabs)

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

        self.generate_button = QPushButton("Generate and Save")
        self.generate_button.setIcon(self._icon("generate.svg"))
        self.generate_button.clicked.connect(self._generate_and_save_rule)

        clear_generate_button = QPushButton("New Rule")
        clear_generate_button.setIcon(self._icon("refresh.svg"))
        clear_generate_button.clicked.connect(self._clear_generate_rule_form)

        generate_actions_layout = QHBoxLayout()
        generate_actions_layout.addWidget(self.generate_button)
        generate_actions_layout.addWidget(clear_generate_button)

        self.generate_status_label = QLabel("")
        self.generate_status_label.setWordWrap(True)

        self.generated_rule_preview = QTextEdit()
        self.generated_rule_preview.setObjectName("rulePreview")
        self.generated_rule_preview.setReadOnly(True)
        self.generated_rule_preview.setPlaceholderText("Generated YARA rule will appear here.")

        behavior_label = QLabel("Detected behaviors")
        behavior_label.setObjectName("behaviorLabel")

        self.behavior_preview = QTextEdit()
        self.behavior_preview.setObjectName("behaviorPreview")
        self.behavior_preview.setReadOnly(True)
        self.behavior_preview.setPlaceholderText("Detected malware behaviors will appear here.")

        layout.addWidget(source_label)
        layout.addLayout(source_layout)
        layout.addWidget(rule_name_label)
        layout.addWidget(self.rule_name_input)
        layout.addLayout(generate_actions_layout)
        layout.addWidget(self.generate_status_label)
        layout.addWidget(self.generated_rule_preview, 2)
        layout.addWidget(behavior_label)
        layout.addWidget(self.behavior_preview, 1)

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

        self.scan_button = QPushButton("Scan File")
        self.scan_button.setIcon(self._icon("play.svg"))
        self.scan_button.clicked.connect(self._scan_file_with_saved_rule)

        clear_scan_button = QPushButton("New Scan")
        clear_scan_button.setIcon(self._icon("refresh.svg"))
        clear_scan_button.clicked.connect(self._clear_scan_file_form)

        scan_actions_layout = QHBoxLayout()
        scan_actions_layout.addWidget(self.scan_button)
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
        self.saved_rules_table.setColumnCount(6)
        self.saved_rules_table.setHorizontalHeaderLabels([
            "ID",
            "Name",
            "Author",
            "Source File",
            "Behaviors",
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
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "ID",
            "Rule",
            "Target File",
            "Matched",
            "Matched Rules",
            "Rule Behaviors",
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
            self.generate_button.setEnabled(False)
            result = self.controller.generate_and_save_rule(source_file, rule_name, self.author_name)

            if isinstance(result, dict) and result.get("success") is False:
                self.generate_status_label.setText(f"Error: {result['message']}")
                self.generated_rule_preview.setPlainText(result.get("rule", ""))
                self.behavior_preview.setPlainText(self._format_behaviors(result.get("behaviors", [])))
                return

            if isinstance(result, dict):
                rule = result["rule"]
                behaviors = result.get("behaviors", [])
            else:
                rule = result
                behaviors = []

            self.generate_status_label.setText(f"Rule saved: {rule.name}")
            self.generated_rule_preview.setPlainText(rule.content)
            self.behavior_preview.setPlainText(self._format_behaviors(behaviors))

        except Exception as e:
            self.generate_status_label.setText(f"Error: {e}")
        finally:
            self.generate_button.setEnabled(True)

    def _clear_generate_rule_form(self):
        self.source_file_input.clear()
        self.rule_name_input.clear()
        self.generate_status_label.clear()
        self.generated_rule_preview.clear()
        self.behavior_preview.clear()

    def _format_behaviors(self, behaviors: list) -> str:
        if not behaviors:
            return "No behavior tags detected."

        lines = []

        for behavior in behaviors:
            name = self._behavior_value(behavior, "name")
            severity = self._behavior_value(behavior, "severity")
            reason = self._behavior_value(behavior, "reason")
            indicators = self._behavior_value(behavior, "indicators") or []

            lines.append(f"{name} ({severity})")
            lines.append(f"Reason: {reason}")
            lines.append("Indicators:")

            for indicator in indicators:
                lines.append(f"  - {indicator}")

            lines.append("")

        return "\n".join(lines).strip()

    def _behavior_value(self, behavior, key: str):
        if isinstance(behavior, dict):
            return behavior.get(key)

        return getattr(behavior, key, None)

    def _behavior_summary(self, behaviors: list) -> str:
        if not behaviors:
            return "None"

        names = []

        for behavior in behaviors:
            name = self._behavior_value(behavior, "name")

            if name and name not in names:
                names.append(name)

        return ", ".join(names) if names else "None"

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

        rules = self._unique_records_by_id(rules)
        self.saved_rules_table.clearContents()
        self.saved_rules_table.setRowCount(0)
        self.saved_rules_table.setRowCount(len(rules))

        for row, rule in enumerate(rules):
            values = [
                rule.get("id"),
                rule.get("name"),
                rule.get("author"),
                rule.get("source_file_name"),
                self._behavior_summary(rule.get("behaviors", [])),
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

        history = self._unique_records_by_id(history)
        self.history_table.clearContents()
        self.history_table.setRowCount(0)
        self.history_table.setRowCount(len(history))

        for row, item in enumerate(history):
            values = [
                item.get("id"),
                item.get("rule_name"),
                item.get("target_file_name"),
                "Yes" if item.get("is_matched") else "No",
                ", ".join(item.get("matched_rules", [])),
                self._behavior_summary(item.get("behaviors", [])),
                item.get("scanned_at"),
            ]

            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _unique_records_by_id(self, records: list) -> list:
        unique_records = []
        seen_ids = set()

        for record in records:
            record_id = record.get("id")

            if record_id in seen_ids:
                continue

            seen_ids.add(record_id)
            unique_records.append(record)

        return unique_records


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
            self.scan_button.setEnabled(False)
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
        finally:
            self.scan_button.setEnabled(True)

    def _clear_scan_file_form(self):
        self.target_file_input.clear()
        self.scan_status_label.clear()
        self.scan_details_preview.clear()
