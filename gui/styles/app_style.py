def build_main_stylesheet(app_background_path: str, panel_background_path: str) -> str:
    """
    Build the main PySide6 stylesheet for the desktop application.
    """
    return """
        QMainWindow {
            background: transparent;
        }

        QWidget#windowFrame {
            background-color: #050608;
            border: 1px solid #26323a;
            border-radius: 24px;
        }

        QWidget#titleBar {
            background-color: #050608;
            border-top-left-radius: 24px;
            border-top-right-radius: 24px;
        }

        QLabel#titleLabel {
            color: #f6fbff;
            font-size: 14px;
            font-weight: 600;
        }

        QWidget#splashScreen {
            border-image: url("__APP_BACKGROUND__") 0 0 0 0 stretch stretch;
            background-color: rgba(5, 8, 10, 235);
            border-bottom-left-radius: 24px;
            border-bottom-right-radius: 24px;
        }

        QLabel#splashTitle {
            color: #ffffff;
            font-size: 48px;
            font-weight: 800;
            letter-spacing: 0;
        }

        QLabel#splashSubtitle {
            color: #bfd2dc;
            font-size: 15px;
        }

        QLabel#splashInputLabel {
            color: #e8eef2;
            font-size: 13px;
            font-weight: 600;
        }

        QLineEdit#authorInput {
            max-width: 360px;
            min-height: 36px;
            color: #ffffff;
            background: rgba(7, 16, 18, 230);
            border: 1px solid #38535b;
            border-radius: 18px;
            padding: 6px 16px;
            selection-background-color: #1f7a72;
        }

        QLineEdit#authorInput:hover,
        QLineEdit#authorInput:focus {
            border-color: #38c7b7;
        }

        QPushButton#startButton {
            min-height: 42px;
            color: #051112;
            background: #38c7b7;
            border: 1px solid #6be0d5;
            border-radius: 21px;
            font-size: 14px;
            font-weight: 700;
        }

        QPushButton#startButton:hover {
            background: #61ddd2;
            border-color: #8af0e8;
        }

        QPushButton#startButton:pressed {
            background: #249488;
            border-color: #38c7b7;
        }

        QTabWidget {
            border-image: url("__APP_BACKGROUND__") 0 0 0 0 stretch stretch;
            border-radius: 0;
        }

        QTabWidget::pane {
            border: 1px solid #26323a;
            background: rgba(5, 8, 10, 210);
            border-bottom-left-radius: 24px;
            border-bottom-right-radius: 24px;
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

        QTabBar::tab:hover {
            color: #ffffff;
            background: #1d2c34;
            border-color: #38c7b7;
        }

        QWidget {
            color: #e8eef2;
            font-size: 13px;
        }

        QLabel {
            color: #e8eef2;
        }

        QLabel#behaviorLabel {
            color: #9ee8df;
            font-size: 13px;
            font-weight: 700;
            padding-top: 4px;
        }

        QLineEdit, QTextEdit, QComboBox, QTableWidget {
            color: #f2f7fa;
            background: rgba(10, 15, 19, 230);
            border: 1px solid #30404a;
            border-radius: 4px;
            padding: 6px;
            selection-background-color: #1f7a72;
        }

        QComboBox:hover {
            border-color: #38c7b7;
        }

        QComboBox::drop-down {
            width: 30px;
            border: none;
            background: transparent;
        }

        QComboBox::down-arrow {
            width: 0;
            height: 0;
        }

        QComboBox QAbstractItemView {
            color: #f2f7fa;
            background-color: #071012;
            border: 1px solid #30404a;
            selection-color: #ffffff;
            selection-background-color: #1f7a72;
            outline: 0;
        }

        QComboBox QAbstractItemView::item {
            min-height: 28px;
            padding: 6px;
            background-color: #071012;
        }

        QComboBox QAbstractItemView::item:hover {
            background-color: #163b38;
            color: #ffffff;
        }

        QTableWidget {
            alternate-background-color: rgba(17, 27, 31, 230);
            gridline-color: #24333a;
            outline: 0;
        }

        QTableWidget::item {
            background-color: rgba(6, 13, 15, 230);
            border: none;
            padding: 4px;
        }

        QTableWidget::item:alternate {
            background-color: rgba(17, 27, 31, 230);
        }

        QTableWidget::item:hover {
            background-color: rgba(34, 132, 120, 170);
            color: #ffffff;
        }

        QTableWidget::item:selected {
            background-color: #1f7a72;
            color: #ffffff;
        }

        QTextEdit#rulePreview, QTextEdit#scanPreview {
            color: #f6fbff;
            border: 1px solid #33515a;
            border-radius: 4px;
            border-image: url("__PANEL_BACKGROUND__") 0 0 0 0 stretch stretch;
            padding: 10px;
            font-family: Consolas, "Courier New", monospace;
            font-size: 13px;
            selection-background-color: #1f7a72;
        }

        QTextEdit#behaviorPreview {
            color: #eaf7f5;
            background: rgba(5, 14, 16, 225);
            border: 1px solid rgba(56, 199, 183, 120);
            border-radius: 8px;
            padding: 10px;
            font-family: Consolas, "Courier New", monospace;
            font-size: 12px;
            selection-background-color: #1f7a72;
        }

        QTextEdit#behaviorPreview:hover {
            border-color: #49d6ca;
        }

        QPushButton {
            color: #ffffff;
            background: #176b63;
            border: 1px solid #2aa89d;
            border-radius: 16px;
            padding: 8px 14px;
        }

        QPushButton:hover {
            background: #1e8178;
            border-color: #49d6ca;
        }

        QPushButton:pressed {
            background: #11524d;
        }

        QPushButton#windowButton {
            color: #d9e7ed;
            background: transparent;
            border: none;
            border-radius: 0;
            padding: 0;
            font-size: 15px;
            font-weight: 600;
        }

        QPushButton#windowButton:hover {
            color: #38c7b7;
            background: transparent;
        }

        QPushButton#windowButton:pressed {
            color: #ffffff;
            background: transparent;
        }

        QPushButton#closeButton {
            color: #d9e7ed;
            background: transparent;
            border: none;
            border-radius: 0;
            padding: 0;
            font-size: 16px;
            font-weight: 600;
        }

        QPushButton#closeButton:hover {
            color: #ff6b6b;
            background: transparent;
        }

        QPushButton#closeButton:pressed {
            color: #ffffff;
            background: transparent;
        }

        QHeaderView::section {
            color: #ffffff;
            background: #14232b;
            border: 1px solid #30404a;
            padding: 6px;
        }
    """.replace("__APP_BACKGROUND__", app_background_path).replace("__PANEL_BACKGROUND__", panel_background_path)
