#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AbuseIPDB Checker — PyQt6 GUI
Professional desktop interface for IP threat intelligence.
"""

import sys
import csv
import datetime
import threading
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QTextEdit, QSpinBox, QDoubleSpinBox,
    QComboBox, QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QFont, QColor, QGuiApplication

# Import core logic from main.py
from main import (
    setup_logging,
    ensure_config,
    config,
    DEFAULTS,
    create_shared_requests_session,
    create_shared_cloudscraper_session,
    fetch_and_parse,
    classify_ip,
    deduplicate_ips,
    filter_and_validate_ips,
    extract_and_clean,
    get_risk_tier,
    RISK_TIERS,
    HAS_CLOUDSCRAPER,
)

import database as db
import pandas as pd

# -------------------------
# Color mapping for risk tiers
# -------------------------
RISK_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#06b6d4",
    "Clean":    "#22c55e",
    "Error":    "#9ca3af",
}

# -------------------------
# Shared stylesheet (Catppuccin Mocha-inspired dark theme)
# -------------------------
STYLESHEET = """
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
}
QTabWidget::pane {
    border: 1px solid #45475a;
    background: #1e1e2e;
    border-radius: 4px;
}
QTabBar::tab {
    background: #313244;
    color: #cdd6f4;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-size: 10pt;
}
QTabBar::tab:selected {
    background: #45475a;
    color: #cba6f7;
    font-weight: bold;
}
QTabBar::tab:hover {
    background: #585b70;
}
QGroupBox {
    border: 1px solid #45475a;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 14px;
    font-weight: bold;
    color: #cba6f7;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 5px 8px;
    font-family: Consolas;
    font-size: 10pt;
    selection-background-color: #585b70;
}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border-color: #cba6f7;
}
QComboBox::drop-down {
    border: none;
    background: #45475a;
    width: 24px;
    border-top-right-radius: 4px;
    border-bottom-right-radius: 4px;
}
QComboBox QAbstractItemView {
    background: #313244;
    color: #cdd6f4;
    selection-background-color: #585b70;
    border: 1px solid #45475a;
}
QPushButton {
    background-color: #45475a;
    color: #cdd6f4;
    border: none;
    border-radius: 4px;
    padding: 7px 18px;
    font-weight: bold;
    font-size: 10pt;
}
QPushButton:hover {
    background-color: #585b70;
}
QPushButton:pressed {
    background-color: #6c7086;
}
QPushButton:disabled {
    background-color: #313244;
    color: #6c7086;
}
QPushButton#accent {
    background-color: #cba6f7;
    color: #1e1e2e;
}
QPushButton#accent:hover {
    background-color: #b4befe;
}
QPushButton#stop {
    background-color: #f38ba8;
    color: #1e1e2e;
}
QPushButton#stop:hover {
    background-color: #eba0ac;
}
QTextEdit {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    font-family: Consolas;
    font-size: 10pt;
    padding: 8px;
    selection-background-color: #585b70;
}
QTableWidget {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    gridline-color: #45475a;
    font-family: Consolas;
    font-size: 9pt;
    selection-background-color: #585b70;
}
QTableWidget::item {
    padding: 4px;
}
QHeaderView::section {
    background-color: #45475a;
    color: #cdd6f4;
    font-weight: bold;
    font-size: 9pt;
    padding: 5px;
    border: none;
    border-right: 1px solid #585b70;
    border-bottom: 1px solid #585b70;
}
QProgressBar {
    background-color: #313244;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background-color: #a6e3a1;
    border-radius: 4px;
}
QScrollBar:vertical {
    background: #1e1e2e;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #45475a;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #585b70;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background: #1e1e2e;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background: #45475a;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover {
    background: #585b70;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
"""

# Column definitions for results table
COLUMNS = ["IP", "Risk", "Confidence", "Reports", "Country", "ISP",
           "Domain", "First Report", "Last Report", "Duration", "Status"]


# -------------------------
# Signal bridge for thread -> GUI communication
# -------------------------
class WorkerSignals(QObject):
    result_ready = pyqtSignal(dict)
    single_done = pyqtSignal(dict, str)
    bulk_finished = pyqtSignal(int, str, str)
    progress_text = pyqtSignal(str)  # status bar text updates from workers
    extract_update = pyqtSignal(dict, int, str)  # (result, count, eta_str)
    extract_done = pyqtSignal(int, float)  # (count, elapsed)
    bulk_progress = pyqtSignal(int, str)  # (count, eta_str)


# -------------------------
# Main Application Window
# -------------------------
class AbuseIPDBApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("AbuseIPDB Checker — Threat Intelligence")
        self.resize(1250, 780)
        self.setMinimumSize(950, 620)

        # Initialize backend
        setup_logging(debug=False)
        ensure_config()
        db.init_db()

        self.all_results: list[dict] = []
        self.is_running = False
        self.signals = WorkerSignals()
        self.signals.result_ready.connect(self._on_bulk_result)
        self.signals.single_done.connect(self._show_single_result)
        self.signals.bulk_finished.connect(self._on_bulk_finished)
        self.signals.progress_text.connect(lambda t: self.status_label.setText(t))
        self.signals.extract_update.connect(self._on_extract_update)
        self.signals.extract_done.connect(self._on_extract_done)
        self.signals.bulk_progress.connect(self._on_bulk_progress)

        self._build_ui()

        # Auto-refresh when switching tabs
        self.tabs.currentChanged.connect(self._on_tab_changed)

    # ===========================
    # Tab Change — smart auto-refresh
    # ===========================
    def _on_tab_changed(self, index: int):
        tab_text = self.tabs.tabText(index).strip()
        if tab_text == "History":
            self._refresh_stats()
        elif tab_text == "Results":
            self._update_results_count()

    # ===========================
    # UI Construction
    # ===========================
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(20, 15, 20, 10)
        root_layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = QLabel("AbuseIPDB Checker")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #cba6f7;")
        header.addWidget(title)
        subtitle = QLabel("Threat Intelligence Tool")
        subtitle.setFont(QFont("Segoe UI", 9))
        subtitle.setStyleSheet("color: #a6adc8; padding-top: 8px;")
        header.addWidget(subtitle)
        header.addStretch()
        root_layout.addLayout(header)

        # Tab widget
        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs, stretch=1)

        self._build_extract_tab()
        self._build_single_tab()
        self._build_bulk_tab()
        self._build_results_tab()
        self._build_history_tab()

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.status_label.setStyleSheet("color: #a6adc8;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(320)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)
        root_layout.addLayout(status_layout)

    # ----- Extract & Check Tab -----
    def _build_extract_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "  Extract & Check  ")
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        # File selection
        file_group = QGroupBox("Source File (logs, CSV, firewall output, any text)")
        file_layout = QHBoxLayout(file_group)
        self.extract_file_input = QLineEdit()
        self.extract_file_input.setPlaceholderText("Select any file containing IP addresses...")
        file_layout.addWidget(self.extract_file_input, stretch=1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._extract_browse)
        file_layout.addWidget(browse_btn)
        layout.addWidget(file_group)

        # Action buttons
        btn_row = QHBoxLayout()
        extract_btn = QPushButton("Extract & Preview")
        extract_btn.setObjectName("accent")
        extract_btn.clicked.connect(self._extract_preview)
        btn_row.addWidget(extract_btn)

        self.extract_check_btn = QPushButton("Extract & Check All")
        self.extract_check_btn.setObjectName("accent")
        self.extract_check_btn.clicked.connect(self._extract_and_check)
        btn_row.addWidget(self.extract_check_btn)

        self.extract_stop_btn = QPushButton("Stop")
        self.extract_stop_btn.setObjectName("stop")
        self.extract_stop_btn.setEnabled(False)
        self.extract_stop_btn.clicked.connect(self._extract_stop)
        btn_row.addWidget(self.extract_stop_btn)

        save_btn = QPushButton("Save Clean List")
        save_btn.clicked.connect(self._extract_save)
        btn_row.addWidget(save_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Progress bar for extract tab
        extract_progress_row = QHBoxLayout()
        self.extract_progress = QProgressBar()
        self.extract_progress.setFixedHeight(10)
        self.extract_progress.setValue(0)
        extract_progress_row.addWidget(self.extract_progress, stretch=1)
        self.extract_eta_label = QLabel("")
        self.extract_eta_label.setFont(QFont("Consolas", 9))
        self.extract_eta_label.setStyleSheet("color: #a6adc8;")
        self.extract_eta_label.setFixedWidth(220)
        extract_progress_row.addWidget(self.extract_eta_label)
        layout.addLayout(extract_progress_row)

        # Stats row
        stats_group = QGroupBox("Extraction Summary")
        stats_layout = QHBoxLayout(stats_group)
        self.extract_stats = {}
        for label in ["IPs Found", "Duplicates Removed", "Private/Invalid Skipped", "Clean Public IPs"]:
            col = QWidget()
            col_lay = QVBoxLayout(col)
            col_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col_lay.setSpacing(2)
            val_lbl = QLabel("—")
            val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
            val_lbl.setStyleSheet("color: #a6e3a1;")
            col_lay.addWidget(val_lbl)
            name_lbl = QLabel(label)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setFont(QFont("Segoe UI", 9))
            name_lbl.setStyleSheet("color: #a6adc8;")
            col_lay.addWidget(name_lbl)
            stats_layout.addWidget(col, stretch=1)
            self.extract_stats[label] = val_lbl
        layout.addWidget(stats_group)

        # Preview table — shows extracted IPs with check results
        preview_group = QGroupBox("Extracted IPs")
        preview_layout = QVBoxLayout(preview_group)

        self.extract_table = QTableWidget()
        self.extract_table.setColumnCount(6)
        self.extract_table.setHorizontalHeaderLabels(
            ["IP Address", "Status", "Risk", "Confidence", "Country", "Reason"]
        )
        self.extract_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.extract_table.horizontalHeader().setStretchLastSection(True)
        self.extract_table.verticalHeader().setVisible(False)
        self.extract_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.extract_table.setSortingEnabled(True)
        self.extract_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        col_widths = [150, 90, 80, 85, 90, 200]
        for i, w in enumerate(col_widths):
            self.extract_table.setColumnWidth(i, w)
        # Double-click → copy IP to clipboard
        self.extract_table.doubleClicked.connect(self._extract_double_click)
        preview_layout.addWidget(self.extract_table)
        layout.addWidget(preview_group, stretch=1)

        # State
        self._extracted_clean_ips: list[str] = []
        self._extracted_skipped: list[dict] = []
        self._extract_running = False
        self._extract_start_time = 0.0
        self._extract_checked_count = 0
        # Map IP -> row index for live updates during check
        self._extract_ip_rows: dict[str, int] = {}

    def _extract_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Extract IPs From", "",
            "All files (*.*);;Text files (*.txt);;Log files (*.log);;CSV files (*.csv)"
        )
        if path:
            self.extract_file_input.setText(path)

    def _extract_populate_table(self, result: dict):
        """Populate extract table with clean + skipped IPs."""
        self._extracted_clean_ips = result["clean_ips"]
        self._extracted_skipped = result["skipped"]

        # Update stats
        self.extract_stats["IPs Found"].setText(str(result["raw_count"]))
        self.extract_stats["Duplicates Removed"].setText(str(result["duplicates_removed"]))
        self.extract_stats["Private/Invalid Skipped"].setText(str(len(result["skipped"])))
        self.extract_stats["Clean Public IPs"].setText(str(result["clean_count"]))

        color = "#a6e3a1" if result["clean_count"] > 0 else "#f38ba8"
        self.extract_stats["Clean Public IPs"].setStyleSheet(f"color: {color};")

        # Populate table
        self.extract_table.setSortingEnabled(False)
        self.extract_table.setRowCount(0)
        self._extract_ip_rows.clear()

        # Clean IPs (green, pending check)
        for ip in result["clean_ips"]:
            row = self.extract_table.rowCount()
            self.extract_table.insertRow(row)
            self._extract_ip_rows[ip] = row

            ip_item = QTableWidgetItem(ip)
            ip_item.setForeground(QColor("#22c55e"))
            self.extract_table.setItem(row, 0, ip_item)

            status_item = QTableWidgetItem("Pending")
            status_item.setForeground(QColor("#a6adc8"))
            self.extract_table.setItem(row, 1, status_item)

            for col in range(2, 6):
                self.extract_table.setItem(row, col, QTableWidgetItem(""))

        # Skipped IPs (dimmed)
        for s in result["skipped"]:
            row = self.extract_table.rowCount()
            self.extract_table.insertRow(row)

            ip_item = QTableWidgetItem(s["IP"])
            ip_item.setForeground(QColor("#6c7086"))
            self.extract_table.setItem(row, 0, ip_item)

            status_item = QTableWidgetItem("Skipped")
            status_item.setForeground(QColor("#f38ba8"))
            self.extract_table.setItem(row, 1, status_item)

            for col in range(2, 5):
                self.extract_table.setItem(row, col, QTableWidgetItem(""))

            reason_item = QTableWidgetItem(s["reason"])
            reason_item.setForeground(QColor("#6c7086"))
            self.extract_table.setItem(row, 5, reason_item)

        self.extract_table.setSortingEnabled(False)  # Keep off during checking

    def _extract_preview(self):
        """Extract only — no checking."""
        file_path = self.extract_file_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Input Required", "Please select a file.")
            return

        result = extract_and_clean(file_path)
        if "error" in result:
            QMessageBox.critical(self, "Error", result["error"])
            return

        self._extract_populate_table(result)
        self.extract_table.setSortingEnabled(True)
        self.status_label.setText(
            f"Extracted {result['raw_count']} IPs — {result['clean_count']} ready to check"
        )

    def _extract_and_check(self):
        """Extract IPs and immediately start checking them."""
        file_path = self.extract_file_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Input Required", "Please select a file.")
            return

        result = extract_and_clean(file_path)
        if "error" in result:
            QMessageBox.critical(self, "Error", result["error"])
            return
        if result["clean_count"] == 0:
            self._extract_populate_table(result)
            QMessageBox.warning(self, "No Valid IPs", "No valid public IPs found after filtering.")
            return

        self._extract_populate_table(result)

        # Setup progress
        import time
        self._extract_running = True
        self._extract_checked_count = 0
        self._extract_start_time = time.time()
        self.extract_progress.setMaximum(result["clean_count"])
        self.extract_progress.setValue(0)
        self.extract_eta_label.setText("")
        self.extract_check_btn.setEnabled(False)
        self.extract_stop_btn.setEnabled(True)

        self.status_label.setText(f"Checking {result['clean_count']} extracted IPs...")

        threading.Thread(
            target=self._extract_check_worker,
            args=(list(result["clean_ips"]),),
            daemon=True
        ).start()

    def _extract_stop(self):
        self._extract_running = False
        self.status_label.setText("Stopping...")

    def _extract_check_worker(self, ips: list[str]):
        """Worker thread: check all extracted IPs with per-thread sessions."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        import threading as _threading

        concurrency = int(config["DEFAULT"].get("concurrency", DEFAULTS["concurrency"]))
        delay = float(config["DEFAULT"].get("delay", DEFAULTS["delay"]))
        ct = float(config["DEFAULT"].get("connectTimeout", DEFAULTS["connectTimeout"]))
        rt = float(config["DEFAULT"].get("timeout", DEFAULTS["timeout"]))
        cache_ttl = float(config["DEFAULT"].get("cacheTTL", DEFAULTS["cacheTTL"]))
        total = len(ips)
        checked = 0
        start = time.time()

        def _calc_eta(count):
            elapsed = time.time() - start
            if count > 0 and elapsed > 0:
                rate = count / elapsed
                remaining = total - count
                eta_secs = remaining / rate if rate > 0 else 0
                return f"{count}/{total}  |  {rate:.1f} IP/s  |  ETA {int(eta_secs)}s"
            return f"{count}/{total}"

        # Check cache first — emit cached results immediately
        ips_to_fetch = []
        for ip in ips:
            if not self._extract_running:
                break
            cached = db.get_cached(ip, ttl_hours=cache_ttl)
            if cached:
                cached["_cached"] = True
                checked += 1
                self.signals.extract_update.emit(cached, checked, _calc_eta(checked))
            else:
                ips_to_fetch.append(ip)

        if not ips_to_fetch or not self._extract_running:
            elapsed = time.time() - start
            self.signals.extract_done.emit(checked, elapsed)
            return

        self.signals.progress_text.emit(
            f"Checking {len(ips_to_fetch)} IPs ({len(ips) - len(ips_to_fetch)} cached)..."
        )

        # Per-thread session factory for better connection handling
        _thread_sessions = _threading.local()

        def _get_sessions():
            if not hasattr(_thread_sessions, "req"):
                _thread_sessions.req = create_shared_requests_session()
                _thread_sessions.cs = create_shared_cloudscraper_session()
            return _thread_sessions.req, _thread_sessions.cs

        def _fetch_ip(ip):
            req_s, cs_s = _get_sessions()
            return fetch_and_parse(ip, req_s, cs_s, delay, ct, rt, HAS_CLOUDSCRAPER)

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(_fetch_ip, ip): ip for ip in ips_to_fetch}

            for future in as_completed(futures):
                if not self._extract_running:
                    ex.shutdown(wait=False, cancel_futures=True)
                    break

                ip_key = futures[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = {"IP": ip_key, "error": str(e)}

                if "error" not in res:
                    tier = get_risk_tier(res.get("Confidence"))
                    res["Risk"] = tier["label"]

                db.store_result(res)
                checked += 1
                self.signals.extract_update.emit(res, checked, _calc_eta(checked))

        elapsed = time.time() - start
        self.signals.extract_done.emit(checked, elapsed)

    def _on_extract_update(self, res: dict, count: int, eta_str: str):
        """Main-thread handler: update extract table row and progress."""
        ip = res.get("IP", "")

        self.extract_progress.setValue(count)
        self.extract_eta_label.setText(eta_str)
        self.status_label.setText(f"Checking IPs... {eta_str}")

        # Update the row in extract table
        if ip in self._extract_ip_rows:
            row = self._extract_ip_rows[ip]
            if "error" in res:
                color = QColor(RISK_COLORS.get("Error", "#9ca3af"))
                self.extract_table.setItem(row, 1, self._colored_item("Error", color))
                self.extract_table.setItem(row, 5, self._colored_item(str(res.get("error", "")), color))
            else:
                risk = res.get("Risk", "Clean")
                color = QColor(RISK_COLORS.get(risk, "#cdd6f4"))
                self.extract_table.setItem(row, 1, self._colored_item("Checked", QColor("#22c55e")))
                self.extract_table.setItem(row, 2, self._colored_item(risk, color))
                self.extract_table.setItem(row, 3, self._colored_item(str(res.get("Confidence", "")), color))
                self.extract_table.setItem(row, 4, self._colored_item(str(res.get("Country", "")), color))

        # Also add to all_results and results tab
        self.all_results.append(res)
        self._update_risk_counter(res)
        # Periodically refresh results page
        if len(self.all_results) % 10 == 0:
            self._results_page = max(0, (len(self._get_filtered_results()) - 1) // self._results_page_size)
            self._load_results_page()

    def _colored_item(self, text: str, color: QColor) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setForeground(color)
        return item

    def _on_extract_done(self, count: int, elapsed: float):
        """Main-thread handler: extract+check complete."""
        self._extract_running = False
        self.extract_check_btn.setEnabled(True)
        self.extract_stop_btn.setEnabled(False)
        self.extract_table.setSortingEnabled(True)
        self.extract_progress.setValue(self.extract_progress.maximum())
        self.extract_eta_label.setText(f"Done in {elapsed:.1f}s")
        self.status_label.setText(f"Done — {count} IPs checked in {elapsed:.1f}s")
        self._refresh_stats()
        self._results_page = 0
        self._load_results_page()

    def _extract_save(self):
        if not self._extracted_clean_ips:
            QMessageBox.information(self, "No Data", "No clean IPs to save. Extract first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Clean IP List", "clean_ips.txt", "Text files (*.txt)"
        )
        if not path:
            return
        try:
            Path(path).write_text("\n".join(self._extracted_clean_ips) + "\n", encoding="utf-8")
            QMessageBox.information(
                self, "Saved",
                f"Saved {len(self._extracted_clean_ips)} clean IPs to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    # ----- Single IP Tab -----
    def _build_single_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "  Single IP  ")
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        # Input group
        input_group = QGroupBox("Check Single IP")
        input_layout = QHBoxLayout(input_group)
        input_layout.addWidget(QLabel("IP Address:"))
        self.single_ip_input = QLineEdit()
        self.single_ip_input.setPlaceholderText("e.g. 8.8.8.8")
        self.single_ip_input.setFixedWidth(260)
        self.single_ip_input.returnPressed.connect(self._check_single)
        input_layout.addWidget(self.single_ip_input)
        check_btn = QPushButton("Check")
        check_btn.setObjectName("accent")
        check_btn.clicked.connect(self._check_single)
        input_layout.addWidget(check_btn)
        input_layout.addStretch()
        layout.addWidget(input_group)

        # Result display
        result_group = QGroupBox("Result")
        result_layout = QVBoxLayout(result_group)
        self.single_result_text = QTextEdit()
        self.single_result_text.setReadOnly(True)
        result_layout.addWidget(self.single_result_text)
        layout.addWidget(result_group, stretch=1)

    # ----- Bulk Check Tab -----
    def _build_bulk_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "  Bulk Check  ")
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        # File selection
        file_group = QGroupBox("Input File (one IP per line)")
        file_layout = QHBoxLayout(file_group)
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select a file...")
        file_layout.addWidget(self.file_path_input, stretch=1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(browse_btn)
        layout.addWidget(file_group)

        # Options
        opts_group = QGroupBox("Options")
        opts_layout = QVBoxLayout(opts_group)

        opts_row = QHBoxLayout()
        opts_row.addWidget(QLabel("Concurrency:"))
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 20)
        self.concurrency_spin.setValue(int(config["DEFAULT"].get("concurrency", DEFAULTS["concurrency"])))
        self.concurrency_spin.setFixedWidth(70)
        opts_row.addWidget(self.concurrency_spin)
        opts_row.addSpacing(20)

        opts_row.addWidget(QLabel("Delay (s):"))
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0.5, 60.0)
        self.delay_spin.setSingleStep(0.5)
        self.delay_spin.setValue(float(config["DEFAULT"].get("delay", DEFAULTS["delay"])))
        self.delay_spin.setFixedWidth(80)
        opts_row.addWidget(self.delay_spin)
        opts_row.addSpacing(20)

        opts_row.addWidget(QLabel("Output base:"))
        self.output_input = QLineEdit("report")
        self.output_input.setFixedWidth(160)
        opts_row.addWidget(self.output_input)
        opts_row.addStretch()
        opts_layout.addLayout(opts_row)

        # Buttons
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start Bulk Check")
        self.start_btn.setObjectName("accent")
        self.start_btn.clicked.connect(self._start_bulk)
        btn_row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_bulk)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()
        opts_layout.addLayout(btn_row)
        layout.addWidget(opts_group)

        # Risk breakdown (live)
        risk_group = QGroupBox("Risk Breakdown (Live)")
        risk_layout = QHBoxLayout(risk_group)
        risk_layout.setSpacing(0)
        self.risk_count_labels: dict[str, QLabel] = {}
        self.risk_name_labels: dict[str, QLabel] = {}

        for tier in RISK_TIERS:
            col_widget = QWidget()
            col_layout = QVBoxLayout(col_widget)
            col_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col_layout.setSpacing(2)

            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            count_lbl.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
            count_lbl.setStyleSheet(f"color: {RISK_COLORS[tier['label']]};")
            col_layout.addWidget(count_lbl)

            name_lbl = QLabel(tier["label"])
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setFont(QFont("Segoe UI", 9))
            name_lbl.setStyleSheet(f"color: {RISK_COLORS[tier['label']]};")
            col_layout.addWidget(name_lbl)

            risk_layout.addWidget(col_widget, stretch=1)
            self.risk_count_labels[tier["label"]] = count_lbl

        # Error column
        col_widget = QWidget()
        col_layout = QVBoxLayout(col_widget)
        col_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col_layout.setSpacing(2)
        err_count = QLabel("0")
        err_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        err_count.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        err_count.setStyleSheet(f"color: {RISK_COLORS['Error']};")
        col_layout.addWidget(err_count)
        err_name = QLabel("Errors")
        err_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        err_name.setFont(QFont("Segoe UI", 9))
        err_name.setStyleSheet(f"color: {RISK_COLORS['Error']};")
        col_layout.addWidget(err_name)
        risk_layout.addWidget(col_widget, stretch=1)
        self.risk_count_labels["Error"] = err_count

        layout.addWidget(risk_group)

        # Bulk progress bar + ETA
        bulk_progress_row = QHBoxLayout()
        self.bulk_progress = QProgressBar()
        self.bulk_progress.setFixedHeight(10)
        self.bulk_progress.setValue(0)
        bulk_progress_row.addWidget(self.bulk_progress, stretch=1)
        self.bulk_eta_label = QLabel("")
        self.bulk_eta_label.setFont(QFont("Consolas", 9))
        self.bulk_eta_label.setStyleSheet("color: #a6adc8;")
        self.bulk_eta_label.setFixedWidth(220)
        bulk_progress_row.addWidget(self.bulk_eta_label)
        layout.addLayout(bulk_progress_row)

        layout.addStretch()

    # ----- Results Tab -----
    def _build_results_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "  Results  ")
        layout = QVBoxLayout(tab)
        layout.setSpacing(8)

        # Toolbar
        toolbar = QHBoxLayout()
        csv_btn = QPushButton("Export CSV")
        csv_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(csv_btn)
        xlsx_btn = QPushButton("Export XLSX")
        xlsx_btn.clicked.connect(self._export_xlsx)
        toolbar.addWidget(xlsx_btn)
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self._clear_results)
        toolbar.addWidget(clear_btn)

        toolbar.addSpacing(20)
        toolbar.addWidget(QLabel("Filter Risk:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All"] + [t["label"] for t in RISK_TIERS] + ["Error"])
        self.filter_combo.setFixedWidth(130)
        self.filter_combo.currentTextChanged.connect(self._apply_filter)
        toolbar.addWidget(self.filter_combo)

        toolbar.addStretch()
        self.results_count_label = QLabel("0 results")
        self.results_count_label.setFont(QFont("Segoe UI", 9))
        self.results_count_label.setStyleSheet("color: #a6adc8;")
        toolbar.addWidget(self.results_count_label)
        layout.addLayout(toolbar)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(False)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Default column widths
        widths = [140, 85, 90, 75, 85, 130, 110, 145, 145, 75, 70]
        for i, w in enumerate(widths):
            self.table.setColumnWidth(i, w)

        # Double-click → copy IP to clipboard
        self.table.doubleClicked.connect(self._results_double_click)

        layout.addWidget(self.table, stretch=1)

        # Results pagination bar
        self._results_page = 0
        self._results_page_size = 100

        res_page_bar = QHBoxLayout()
        self.res_first_btn = QPushButton("First")
        self.res_first_btn.setFixedWidth(60)
        self.res_first_btn.clicked.connect(lambda: self._results_go_page(0))
        res_page_bar.addWidget(self.res_first_btn)

        self.res_prev_btn = QPushButton("Prev")
        self.res_prev_btn.setFixedWidth(60)
        self.res_prev_btn.clicked.connect(lambda: self._results_go_page(self._results_page - 1))
        res_page_bar.addWidget(self.res_prev_btn)

        self.res_page_label = QLabel("Page 1 of 1")
        self.res_page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.res_page_label.setFont(QFont("Segoe UI", 9))
        self.res_page_label.setStyleSheet("color: #cdd6f4;")
        self.res_page_label.setFixedWidth(150)
        res_page_bar.addWidget(self.res_page_label)

        self.res_next_btn = QPushButton("Next")
        self.res_next_btn.setFixedWidth(60)
        self.res_next_btn.clicked.connect(lambda: self._results_go_page(self._results_page + 1))
        res_page_bar.addWidget(self.res_next_btn)

        self.res_last_btn = QPushButton("Last")
        self.res_last_btn.setFixedWidth(60)
        self.res_last_btn.clicked.connect(lambda: self._results_go_page(-1))  # -1 = last
        res_page_bar.addWidget(self.res_last_btn)

        res_page_bar.addSpacing(20)
        res_page_bar.addWidget(QLabel("Per page:"))
        self.res_page_size_combo = QComboBox()
        self.res_page_size_combo.addItems(["50", "100", "200", "500"])
        self.res_page_size_combo.setCurrentText("100")
        self.res_page_size_combo.setFixedWidth(80)
        self.res_page_size_combo.currentTextChanged.connect(self._results_page_size_changed)
        res_page_bar.addWidget(self.res_page_size_combo)

        res_page_bar.addStretch()
        layout.addLayout(res_page_bar)

    # ----- History Tab -----
    def _build_history_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "  History  ")
        layout = QVBoxLayout(tab)
        layout.setSpacing(8)

        # Stats panel
        stats_group = QGroupBox("Database Statistics")
        stats_layout = QHBoxLayout(stats_group)
        self.stats_labels = {}
        for stat_name in ["Total Checks", "Unique IPs", "Errors", "Last Check"]:
            col = QWidget()
            col_layout = QVBoxLayout(col)
            col_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col_layout.setSpacing(2)
            val_lbl = QLabel("—")
            val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
            val_lbl.setStyleSheet("color: #cba6f7;")
            col_layout.addWidget(val_lbl)
            name_lbl = QLabel(stat_name)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setFont(QFont("Segoe UI", 9))
            name_lbl.setStyleSheet("color: #a6adc8;")
            col_layout.addWidget(name_lbl)
            stats_layout.addWidget(col, stretch=1)
            self.stats_labels[stat_name] = val_lbl
        layout.addWidget(stats_group)

        # Search / filter toolbar
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Search IP:"))
        self.history_search = QLineEdit()
        self.history_search.setPlaceholderText("e.g. 8.8.8")
        self.history_search.setFixedWidth(200)
        self.history_search.returnPressed.connect(self._history_search_triggered)
        toolbar.addWidget(self.history_search)

        toolbar.addSpacing(15)
        toolbar.addWidget(QLabel("Risk:"))
        self.history_risk_filter = QComboBox()
        self.history_risk_filter.addItems(["All"] + [t["label"] for t in RISK_TIERS] + ["Error"])
        self.history_risk_filter.setFixedWidth(120)
        self.history_risk_filter.currentTextChanged.connect(self._history_search_triggered)
        toolbar.addWidget(self.history_risk_filter)

        toolbar.addSpacing(15)
        search_btn = QPushButton("Search")
        search_btn.setObjectName("accent")
        search_btn.clicked.connect(self._history_search_triggered)
        toolbar.addWidget(search_btn)

        refresh_btn = QPushButton("Refresh Stats")
        refresh_btn.clicked.connect(self._refresh_stats)
        toolbar.addWidget(refresh_btn)

        toolbar.addStretch()

        purge_btn = QPushButton("Purge Old (90d)")
        purge_btn.clicked.connect(self._purge_old)
        toolbar.addWidget(purge_btn)

        self.history_count_label = QLabel("")
        self.history_count_label.setFont(QFont("Segoe UI", 9))
        self.history_count_label.setStyleSheet("color: #a6adc8;")
        toolbar.addWidget(self.history_count_label)
        layout.addLayout(toolbar)

        # History table
        hist_columns = ["IP", "Risk", "Confidence", "Reports", "Country",
                        "ISP", "Domain", "Checked At"]
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(len(hist_columns))
        self.history_table.setHorizontalHeaderLabels(hist_columns)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setSortingEnabled(True)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hist_widths = [140, 85, 90, 75, 90, 140, 110, 170]
        for i, w in enumerate(hist_widths):
            self.history_table.setColumnWidth(i, w)

        # Double-click a row → re-check that IP in Single IP tab
        self.history_table.doubleClicked.connect(self._history_double_click)

        layout.addWidget(self.history_table, stretch=1)

        # Pagination bar
        self._history_page = 0
        self._history_page_size = 100

        page_bar = QHBoxLayout()
        self.hist_first_btn = QPushButton("First")
        self.hist_first_btn.setFixedWidth(60)
        self.hist_first_btn.clicked.connect(lambda: self._history_go_page(0))
        page_bar.addWidget(self.hist_first_btn)

        self.hist_prev_btn = QPushButton("Prev")
        self.hist_prev_btn.setFixedWidth(60)
        self.hist_prev_btn.clicked.connect(lambda: self._history_go_page(self._history_page - 1))
        page_bar.addWidget(self.hist_prev_btn)

        self.hist_page_label = QLabel("Page 1 of 1")
        self.hist_page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hist_page_label.setFont(QFont("Segoe UI", 9))
        self.hist_page_label.setStyleSheet("color: #cdd6f4;")
        self.hist_page_label.setFixedWidth(150)
        page_bar.addWidget(self.hist_page_label)

        self.hist_next_btn = QPushButton("Next")
        self.hist_next_btn.setFixedWidth(60)
        self.hist_next_btn.clicked.connect(lambda: self._history_go_page(self._history_page + 1))
        page_bar.addWidget(self.hist_next_btn)

        self.hist_last_btn = QPushButton("Last")
        self.hist_last_btn.setFixedWidth(60)
        self.hist_last_btn.clicked.connect(lambda: self._history_go_page(self._history_total_pages - 1))
        page_bar.addWidget(self.hist_last_btn)

        page_bar.addSpacing(20)
        page_bar.addWidget(QLabel("Per page:"))
        self.hist_page_size_combo = QComboBox()
        self.hist_page_size_combo.addItems(["50", "100", "200", "500"])
        self.hist_page_size_combo.setCurrentText("100")
        self.hist_page_size_combo.setFixedWidth(80)
        self.hist_page_size_combo.currentTextChanged.connect(self._history_page_size_changed)
        page_bar.addWidget(self.hist_page_size_combo)

        page_bar.addStretch()
        layout.addLayout(page_bar)

        self._history_total_pages = 1

        # Load initial data
        self._refresh_stats()

    def _refresh_stats(self):
        try:
            stats = db.get_stats()
            self.stats_labels["Total Checks"].setText(str(stats["total_checks"]))
            self.stats_labels["Unique IPs"].setText(str(stats["unique_ips"]))
            self.stats_labels["Errors"].setText(str(stats["errors"]))
            self.stats_labels["Last Check"].setText(str(stats["last_check"] or "—"))
        except Exception:
            pass
        self._load_history()

    def _load_history(self):
        ip_filter = self.history_search.text().strip()
        risk_filter = self.history_risk_filter.currentText()
        page_size = self._history_page_size
        offset = self._history_page * page_size

        try:
            count = db.get_history_count(ip_filter=ip_filter, risk_filter=risk_filter)
            records = db.get_history(
                ip_filter=ip_filter, risk_filter=risk_filter,
                limit=page_size, offset=offset,
            )
        except Exception:
            records = []
            count = 0

        # Update pagination state
        self._history_total_pages = max(1, (count + page_size - 1) // page_size)
        if self._history_page >= self._history_total_pages:
            self._history_page = self._history_total_pages - 1

        self.history_table.setSortingEnabled(False)
        self.history_table.setRowCount(0)

        for rec in records:
            risk = rec.get("Risk", "")
            tag = risk if risk in [t["label"] for t in RISK_TIERS] else "Error"
            color = QColor(RISK_COLORS.get(tag, "#cdd6f4"))

            values = [
                str(rec.get("IP", "")),
                risk,
                str(rec.get("Confidence", "")),
                str(rec.get("Reports", "")),
                str(rec.get("Country", "")),
                str(rec.get("ISP", "")),
                str(rec.get("Domain", "")),
                str(rec.get("checked_at", "")),
            ]

            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            for col_idx, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setForeground(color)
                self.history_table.setItem(row, col_idx, item)

        self.history_table.setSortingEnabled(True)

        # Update pagination controls
        page_num = self._history_page + 1
        self.hist_page_label.setText(f"Page {page_num} of {self._history_total_pages}")
        self.hist_first_btn.setEnabled(self._history_page > 0)
        self.hist_prev_btn.setEnabled(self._history_page > 0)
        self.hist_next_btn.setEnabled(self._history_page < self._history_total_pages - 1)
        self.hist_last_btn.setEnabled(self._history_page < self._history_total_pages - 1)

        start = offset + 1
        end = min(offset + len(records), count)
        self.history_count_label.setText(f"{start}–{end} of {count}")

    def _history_go_page(self, page: int):
        page = max(0, min(page, self._history_total_pages - 1))
        if page != self._history_page:
            self._history_page = page
            self._load_history()

    def _history_page_size_changed(self, text: str):
        self._history_page_size = int(text)
        self._history_page = 0
        self._load_history()

    def _history_search_triggered(self):
        """Reset to first page and reload when search/filter changes."""
        self._history_page = 0
        self._load_history()

    def _purge_old(self):
        reply = QMessageBox.question(
            self, "Purge Old Records",
            "Delete all records older than 90 days?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            deleted = db.delete_old_records(days=90)
            QMessageBox.information(self, "Purged", f"Deleted {deleted} old records.")
            self._refresh_stats()

    # ===========================
    # Single IP Check
    # ===========================
    def _check_single(self):
        ip = self.single_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Required", "Please enter an IP address.")
            return

        reason = classify_ip(ip)
        if reason:
            self._show_single_result({"IP": ip, "error": f"Skipped — {reason}"}, ip)
            return

        self.status_label.setText(f"Checking {ip}...")
        self.single_result_text.setHtml(
            f'<span style="color:#a6adc8;">Checking {ip}...</span>'
        )

        threading.Thread(target=self._single_worker, args=(ip,), daemon=True).start()

    def _single_worker(self, ip):
        cache_ttl = float(config["DEFAULT"].get("cacheTTL", DEFAULTS["cacheTTL"]))
        cached = db.get_cached(ip, ttl_hours=cache_ttl)
        if cached:
            cached["_cached"] = True
            self.signals.single_done.emit(cached, ip)
            return

        req_session = create_shared_requests_session()
        cs_session = create_shared_cloudscraper_session()
        delay = float(config["DEFAULT"].get("delay", DEFAULTS["delay"]))
        ct = float(config["DEFAULT"].get("connectTimeout", DEFAULTS["connectTimeout"]))
        rt = float(config["DEFAULT"].get("timeout", DEFAULTS["timeout"]))

        res = fetch_and_parse(ip, req_session, cs_session, base_delay=delay,
                              connect_timeout=ct, read_timeout=rt, use_cloudscraper_fallback=HAS_CLOUDSCRAPER)
        if not res:
            res = {"IP": ip, "error": "No result returned"}
        if "error" not in res:
            tier = get_risk_tier(res.get("Confidence"))
            res["Risk"] = tier["label"]

        db.store_result(res)
        self.signals.single_done.emit(res, ip)

    def _show_single_result(self, res: dict, ip: str):
        self.status_label.setText("Ready")

        if "error" in res:
            self.single_result_text.setHtml(
                f'<span style="color:#f38ba8; font-size:11pt; font-weight:bold;">{ip}</span><br>'
                f'<span style="color:#f38ba8;">{res["error"]}</span>'
            )
            return

        tier = get_risk_tier(res.get("Confidence"))
        color = RISK_COLORS.get(tier["label"], "#cdd6f4")

        cache_note = ""
        if res.get("_cached"):
            cache_note = (f'<span style="color:#a6adc8; font-size:9pt;">'
                          f'(cached — checked at {res.get("checked_at", "?")})</span><br>')

        lines = [
            f'<span style="color:{color}; font-size:13pt; font-weight:bold;">{ip}</span><br>',
            cache_note,
            f'<span style="color:#a6adc8;">Risk Level: </span>'
            f'<span style="color:{color}; font-weight:bold; font-size:12pt;">{tier["label"]}</span><br><br>',
        ]

        fields = [
            ("Confidence", f"{res.get('Confidence', 'N/A')}%"),
            ("Reports", res.get("Reports", "N/A")),
            ("Country", res.get("Country", "")),
            ("ISP", res.get("ISP", "")),
            ("Usage Type", res.get("Usage Type", "")),
            ("ASN", res.get("ASN", "")),
            ("Domain", res.get("Domain", "")),
            ("Hostname(s)", res.get("Hostname(s)", "")),
            ("City", res.get("City", "")),
            ("First Report", res.get("First Report UTC", "N/A")),
            ("Last Report", res.get("Last Report UTC", "N/A")),
            ("Found in DB", "Yes" if res.get("Found") else "No"),
            ("Duration", f"{res.get('Duration', 'N/A')}s"),
            ("Attempts", res.get("Attempts", "N/A")),
        ]
        for label, val in fields:
            lines.append(
                f'<span style="color:#a6adc8;">{label:>16}: </span>'
                f'<span style="color:#cdd6f4;">{val}</span><br>'
            )
        lines.append(f'<br><span style="color:#cdd6f4;">Link: {res.get("Link", "")}</span>')

        self.single_result_text.setHtml(
            '<pre style="font-family:Consolas; font-size:10pt; line-height:1.5;">'
            + "".join(lines)
            + '</pre>'
        )

        # Add to results table
        self.all_results.append(res)
        self._results_page = max(0, (len(self._get_filtered_results()) - 1) // self._results_page_size)
        self._load_results_page()
        self._refresh_stats()

    # ===========================
    # Bulk Check
    # ===========================
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select IP List", "",
            "Text files (*.txt);;CSV files (*.csv);;All files (*.*)"
        )
        if path:
            self.file_path_input.setText(path)

    def _start_bulk(self):
        file_path = self.file_path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Input Required", "Please select a file.")
            return
        fp = Path(file_path)
        if not fp.exists():
            QMessageBox.critical(self, "File Not Found", f"File not found:\n{file_path}")
            return

        with open(fp, "r", encoding="utf-8") as f:
            raw_ips = [line.strip() for line in f if line.strip()]

        if not raw_ips:
            QMessageBox.warning(self, "Empty File", "The file contains no IPs.")
            return

        # Dedup & validate
        ips, dup_count = deduplicate_ips(raw_ips)
        ips, skipped = filter_and_validate_ips(ips)

        info_parts = []
        if dup_count:
            info_parts.append(f"{dup_count} duplicate(s) removed")
        if skipped:
            info_parts.append(f"{len(skipped)} non-routable/invalid IP(s) skipped")

        if not ips:
            QMessageBox.warning(self, "No Valid IPs",
                                "No valid public IPs after filtering.\n" + "\n".join(info_parts))
            return

        # Show pre-processing info in status bar (non-blocking)
        if info_parts:
            self.status_label.setText(f"{len(ips)} valid IPs — " + ", ".join(info_parts))

        self.is_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setMaximum(len(ips))
        self.progress_bar.setValue(0)
        self.bulk_progress.setMaximum(len(ips))
        self.bulk_progress.setValue(0)
        self.bulk_eta_label.setText("")

        # Reset risk counters
        for lbl in self.risk_count_labels.values():
            lbl.setText("0")

        concurrency = self.concurrency_spin.value()
        delay = self.delay_spin.value()
        output_base = self.output_input.text().strip() or "report"

        self.status_label.setText(f"Checking {len(ips)} IPs...")
        threading.Thread(
            target=self._bulk_worker,
            args=(ips, concurrency, delay, output_base),
            daemon=True
        ).start()

    def _stop_bulk(self):
        self.is_running = False
        self.status_label.setText("Stopping...")

    def _bulk_worker(self, ips, concurrency, delay, output_base):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        import threading as _threading

        ct = float(config["DEFAULT"].get("connectTimeout", DEFAULTS["connectTimeout"]))
        rt = float(config["DEFAULT"].get("timeout", DEFAULTS["timeout"]))
        cache_ttl = float(config["DEFAULT"].get("cacheTTL", DEFAULTS["cacheTTL"]))
        total = len(ips)
        checked = 0
        start = time.time()

        def _calc_eta(count):
            elapsed = time.time() - start
            if count > 0 and elapsed > 0:
                rate = count / elapsed
                remaining = total - count
                eta_secs = remaining / rate if rate > 0 else 0
                return f"{count}/{total}  |  {rate:.1f} IP/s  |  ETA {int(eta_secs)}s"
            return f"{count}/{total}"

        fieldnames = [
            "IP", "Risk", "Confidence", "Reports", "Country", "ISP", "Usage Type", "ASN",
            "Domain", "Hostname(s)", "City", "First Report UTC", "Last Report UTC",
            "Link", "Found", "Duration", "Attempts", "SessionType", "error"
        ]

        csv_path = Path(f"{output_base}.csv")
        xlsx_path = Path(f"{output_base}.xlsx")

        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
        except Exception:
            pass

        results = []

        # Check cache first
        ips_to_fetch = []
        for ip in ips:
            if not self.is_running:
                break
            cached = db.get_cached(ip, ttl_hours=cache_ttl)
            if cached:
                cached["_cached"] = True
                results.append(cached)
                checked += 1
                self.signals.result_ready.emit(cached)
                self.signals.bulk_progress.emit(checked, _calc_eta(checked))
                try:
                    with open(csv_path, "a", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writerow(cached)
                except Exception:
                    pass
            else:
                ips_to_fetch.append(ip)

        if ips_to_fetch and self.is_running:
            self.signals.progress_text.emit(
                f"Checking {len(ips_to_fetch)} IPs ({len(ips) - len(ips_to_fetch)} cached)..."
            )

            # Per-thread session factory
            _thread_sessions = _threading.local()

            def _get_sessions():
                if not hasattr(_thread_sessions, "req"):
                    _thread_sessions.req = create_shared_requests_session()
                    _thread_sessions.cs = create_shared_cloudscraper_session()
                return _thread_sessions.req, _thread_sessions.cs

            def _fetch_ip(ip):
                req_s, cs_s = _get_sessions()
                return fetch_and_parse(ip, req_s, cs_s, delay, ct, rt, HAS_CLOUDSCRAPER)

            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = {ex.submit(_fetch_ip, ip): ip for ip in ips_to_fetch}

                for future in as_completed(futures):
                    if not self.is_running:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break

                    ip_key = futures[future]
                    try:
                        res = future.result()
                    except Exception as e:
                        res = {"IP": ip_key, "error": str(e)}

                    if "error" not in res:
                        tier = get_risk_tier(res.get("Confidence"))
                        res["Risk"] = tier["label"]

                    db.store_result(res)
                    results.append(res)

                    try:
                        with open(csv_path, "a", newline="", encoding="utf-8") as f:
                            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                            writer.writerow(res)
                    except Exception:
                        pass

                    checked += 1
                    self.signals.result_ready.emit(res)
                    self.signals.bulk_progress.emit(checked, _calc_eta(checked))

        # Final XLSX export
        if results:
            try:
                df = pd.DataFrame(results)
                existing_cols = [c for c in fieldnames if c in df.columns]
                df = df[existing_cols]
                df.to_excel(xlsx_path, index=False)
            except Exception:
                pass

        self.signals.bulk_finished.emit(len(results), str(csv_path), str(xlsx_path))

    def _on_bulk_result(self, res: dict):
        self.all_results.append(res)
        self._update_risk_counter(res)
        self.progress_bar.setValue(self.progress_bar.value() + 1)
        # Auto-refresh results page every 10 results or when on last page
        if len(self.all_results) % 10 == 0:
            self._results_page = max(0, (len(self._get_filtered_results()) - 1) // self._results_page_size)
            self._load_results_page()

    def _on_bulk_progress(self, count: int, eta_str: str):
        """Main-thread handler: update bulk tab progress bar and ETA."""
        self.bulk_progress.setValue(count)
        self.bulk_eta_label.setText(eta_str)
        self.status_label.setText(f"Checking IPs... {eta_str}")

    def _on_bulk_finished(self, count: int, csv_path: str, xlsx_path: str):
        self.is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.bulk_progress.setValue(self.bulk_progress.maximum())
        self.bulk_eta_label.setText("Done")
        self.status_label.setText(f"Done — {count} IPs checked")
        self._results_page = 0  # Show first page of results
        self._load_results_page()
        self.tabs.setCurrentIndex(3)  # Switch to results tab
        self._refresh_stats()
        QMessageBox.information(self, "Bulk Check Complete",
                                f"Checked {count} IPs.\n\nCSV: {csv_path}\nXLSX: {xlsx_path}")

    # ===========================
    # Results Table Helpers
    # ===========================
    def _update_risk_counter(self, res: dict):
        key = "Error" if "error" in res else res.get("Risk", "Clean")
        if key in self.risk_count_labels:
            current = int(self.risk_count_labels[key].text())
            self.risk_count_labels[key].setText(str(current + 1))

    def _update_results_count(self):
        self._load_results_page()

    def _get_filtered_results(self) -> list[dict]:
        """Return all_results filtered by current risk filter."""
        current_filter = self.filter_combo.currentText()
        if current_filter == "All":
            return self.all_results
        filtered = []
        for res in self.all_results:
            risk = res.get("Risk", "Error" if "error" in res else "")
            tag = risk if risk in [t["label"] for t in RISK_TIERS] else "Error"
            if tag == current_filter:
                filtered.append(res)
        return filtered

    def _load_results_page(self):
        """Render the current page of results into the table."""
        filtered = self._get_filtered_results()
        total = len(filtered)
        page_size = self._results_page_size
        total_pages = max(1, (total + page_size - 1) // page_size)

        # Clamp page
        if self._results_page >= total_pages:
            self._results_page = total_pages - 1
        if self._results_page < 0:
            self._results_page = 0

        start = self._results_page * page_size
        end = min(start + page_size, total)
        page_data = filtered[start:end]

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        for res in page_data:
            risk = res.get("Risk", "Error" if "error" in res else "")
            tag = risk if risk in [t["label"] for t in RISK_TIERS] else "Error"
            color = QColor(RISK_COLORS.get(tag, "#cdd6f4"))

            values = [
                res.get("IP", "?"),
                risk,
                str(res.get("Confidence", "")),
                str(res.get("Reports", "")),
                str(res.get("Country", "")),
                str(res.get("ISP", "")),
                str(res.get("Domain", "")),
                str(res.get("First Report UTC", "")),
                str(res.get("Last Report UTC", "")),
                str(res.get("Duration", "")),
                "Error" if "error" in res else "OK",
            ]

            row = self.table.rowCount()
            self.table.insertRow(row)
            for col_idx, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setForeground(color)
                if col_idx in (2, 3, 9):
                    try:
                        item.setData(Qt.ItemDataRole.UserRole, float(val) if val else 0)
                    except ValueError:
                        pass
                self.table.setItem(row, col_idx, item)

        self.table.setSortingEnabled(True)

        # Update pagination controls
        page_num = self._results_page + 1
        self.res_page_label.setText(f"Page {page_num} of {total_pages}")
        self.res_first_btn.setEnabled(self._results_page > 0)
        self.res_prev_btn.setEnabled(self._results_page > 0)
        self.res_next_btn.setEnabled(self._results_page < total_pages - 1)
        self.res_last_btn.setEnabled(self._results_page < total_pages - 1)

        if total > 0:
            self.results_count_label.setText(f"{start + 1}–{end} of {total}")
        else:
            self.results_count_label.setText("0 results")

    def _results_go_page(self, page: int):
        filtered = self._get_filtered_results()
        total_pages = max(1, (len(filtered) + self._results_page_size - 1) // self._results_page_size)
        if page < 0:
            page = total_pages - 1  # -1 means last page
        page = max(0, min(page, total_pages - 1))
        if page != self._results_page:
            self._results_page = page
            self._load_results_page()

    def _results_page_size_changed(self, text: str):
        self._results_page_size = int(text)
        self._results_page = 0
        self._load_results_page()

    # ===========================
    # Filter
    # ===========================
    def _apply_filter(self):
        self._results_page = 0
        self._load_results_page()

    # ===========================
    # Smart Interactions
    # ===========================
    def _copy_ip_to_clipboard(self, table: QTableWidget, row: int):
        """Copy the IP from the first column of the given row to clipboard."""
        item = table.item(row, 0)
        if item:
            QGuiApplication.clipboard().setText(item.text())
            self.status_label.setText(f"Copied: {item.text()}")
            # Reset status after 2 seconds
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def _extract_double_click(self, index):
        self._copy_ip_to_clipboard(self.extract_table, index.row())

    def _results_double_click(self, index):
        self._copy_ip_to_clipboard(self.table, index.row())

    def _history_double_click(self, index):
        """Double-click in history → load IP into Single IP tab and check it."""
        item = self.history_table.item(index.row(), 0)
        if item:
            ip = item.text()
            self.single_ip_input.setText(ip)
            self.tabs.setCurrentIndex(1)  # Switch to Single IP tab
            self._check_single()

    # ===========================
    # Export
    # ===========================
    def _export_csv(self):
        if not self.all_results:
            QMessageBox.information(self, "No Data", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", f"abuseipdb_report_{datetime.date.today()}.csv",
            "CSV files (*.csv)"
        )
        if not path:
            return
        fieldnames = [
            "IP", "Risk", "Confidence", "Reports", "Country", "ISP", "Usage Type", "ASN",
            "Domain", "Hostname(s)", "City", "First Report UTC", "Last Report UTC",
            "Link", "Found", "Duration", "Attempts", "SessionType", "error"
        ]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.all_results)
            QMessageBox.information(self, "Exported", f"CSV saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_xlsx(self):
        if not self.all_results:
            QMessageBox.information(self, "No Data", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export XLSX", f"abuseipdb_report_{datetime.date.today()}.xlsx",
            "Excel files (*.xlsx)"
        )
        if not path:
            return
        try:
            df = pd.DataFrame(self.all_results)
            df.to_excel(path, index=False)
            QMessageBox.information(self, "Exported", f"XLSX saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _clear_results(self):
        if not self.all_results:
            return
        reply = QMessageBox.question(self, "Confirm", "Clear all results?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.all_results.clear()
            for lbl in self.risk_count_labels.values():
                lbl.setText("0")
            self._results_page = 0
            self._load_results_page()


# -------------------------
# Entry Point
# -------------------------
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    app.setFont(QFont("Segoe UI", 10))
    window = AbuseIPDBApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
