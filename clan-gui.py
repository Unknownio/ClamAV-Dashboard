import sys
import os
import signal
import subprocess
import threading
import time
import shutil
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QFrame, QScrollArea, QSplitter,
    QStackedWidget, QListWidget, QListWidgetItem, QTextEdit, QLineEdit,
    QMessageBox, QAbstractItemView
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize
)
from PyQt5.QtGui import (
    QColor, QFont
)

# ── Quarantine directory ─────────────────────────────────────────────────────
QUARANTINE_DIR = os.path.join(Path.home(), ".clamav_web_ui_client_quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Manifest: maps quarantine filename → {"original": str, "threat": str, "date": str}
QUARANTINE_MANIFEST = os.path.join(QUARANTINE_DIR, ".manifest.json")

def _load_manifest():
    try:
        import json
        with open(QUARANTINE_MANIFEST) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_manifest(data):
    import json
    with open(QUARANTINE_MANIFEST, "w") as f:
        json.dump(data, f, indent=2)

def quarantine_file(original_path, threat_name):
    """Move file to quarantine dir, strip all permissions. Returns quarantine path or None."""
    try:
        import json, uuid
        # Give it a unique name so collisions don't overwrite
        safe_name = f"{uuid.uuid4().hex}_{os.path.basename(original_path)}"
        dest = os.path.join(QUARANTINE_DIR, safe_name)
        shutil.move(original_path, dest)
        os.chmod(dest, 0o000)   # no read/write/execute for anyone

        manifest = _load_manifest()
        manifest[safe_name] = {
            "original": original_path,
            "threat":   threat_name,
            "date":     datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        _save_manifest(manifest)
        return dest, safe_name
    except Exception as e:
        return None, str(e)

def restore_file(safe_name):
    """Restore file from quarantine to original location. Returns (ok, msg)."""
    try:
        manifest = _load_manifest()
        if safe_name not in manifest:
            return False, "Not found in manifest."
        original = manifest[safe_name]["original"]
        src = os.path.join(QUARANTINE_DIR, safe_name)
        os.chmod(src, 0o644)
        shutil.move(src, original)
        del manifest[safe_name]
        _save_manifest(manifest)
        return True, original
    except Exception as e:
        return False, str(e)

def delete_quarantined(safe_name):
    """Permanently delete a quarantined file. Returns (ok, msg)."""
    try:
        manifest = _load_manifest()
        src = os.path.join(QUARANTINE_DIR, safe_name)
        if os.path.exists(src):
            os.chmod(src, 0o644)   # need read perms to delete on some systems
            os.remove(src)
        if safe_name in manifest:
            del manifest[safe_name]
            _save_manifest(manifest)
        return True, "Deleted."
    except Exception as e:
        return False, str(e)

# ── Colour palette ───────────────────────────────────────────────────────────
BG_DARK   = "#0a0e1a"
BG_CARD   = "#0f172a"
BG_SIDE   = "#080c16"
BORDER    = "#1e293b"
ACCENT    = ""
ACCENT2   = "#8b5cf6"
GREEN     = "#10b981"
RED       = "#ef4444"
YELLOW    = "#f59e0b"
TEXT_PRI  = "#f1f5f9"
TEXT_SEC  = "#64748b"
TEXT_MUT  = "#334155"

STYLE = f"""
QMainWindow, QWidget {{
    background: {BG_DARK};
    color: {TEXT_PRI};
    font-family: 'Segoe UI', 'SF Pro Display', Arial, sans-serif;
}}
QLabel {{ color: {TEXT_PRI}; background: transparent; }}
QScrollBar:vertical {{
    background: {BG_DARK}; width: 6px; border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 3px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ height: 0; }}
QTableWidget {{
    background: {BG_CARD}; border: none;
    border-radius: 10px; gridline-color: {BORDER};
    selection-background-color: #1e293b;
}}
QTableWidget::item {{ border: none; color: {TEXT_PRI}; }}
QTableWidget::item:selected {{ background: #1e293b; }}
QHeaderView::section {{
    background: {BG_DARK}; color: {TEXT_SEC}; border: none;
    border-bottom: 1px solid {BORDER};
    font-size: 10px; letter-spacing: 1px;
}}
QProgressBar {{
    background: {BG_DARK}; border: none; border-radius: 3px; height: 4px;
}}
QProgressBar::chunk {{ border-radius: 3px; }}
QLineEdit {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 8px; color: {TEXT_PRI}; font-size: 13px;
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QTextEdit {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 10px; color: {TEXT_SEC}; font-size: 12px;
    font-family: 'Consolas', 'Courier New', monospace;
}}
QListWidget {{
    background: transparent; border: none; outline: none;
}}
QListWidget::item {{
    border: none; color: {TEXT_PRI};
}}
QListWidget::item:selected {{
    background: {BORDER}; border-radius: 6px; color: {TEXT_PRI};
}}
QPushButton {{
    outline: none; border: none;
}}
QPushButton:focus {{
    outline: none; border: none;
}}
"""


# ── Persistence ─────────────────────────────────────────────────────────────
LAST_SCAN_FILE = os.path.join(Path.home(), ".clamav_web_ui_client_last_scan")

def save_last_scan():
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(datetime.now().isoformat())

def load_last_scan():
    try:
        with open(LAST_SCAN_FILE) as f:
            dt = datetime.fromisoformat(f.read().strip())
        delta = datetime.now() - dt
        days = delta.days
        if days == 0:
            label_str = f"Today at {dt.strftime('%H:%M')}"
        elif days == 1:
            label_str = f"Yesterday at {dt.strftime('%H:%M')}"
        else:
            label_str = f"{days} days ago  ({dt.strftime('%d %b %Y')})"
        return dt, label_str, days
    except Exception:
        return None, "Never", 9999


# ── ClamAV check ─────────────────────────────────────────────────────────────
def clamscan_available():
    return shutil.which("clamscan") is not None

def count_files(paths):
    total = 0
    for p in paths:
        if os.path.isfile(p):
            total += 1
        elif os.path.isdir(p):
            for _, _, files in os.walk(p):
                total += len(files)
    return total


# ── Worker thread ────────────────────────────────────────────────────────────
class ScanWorker(QThread):
    progress  = pyqtSignal(int, int)
    file_done = pyqtSignal(dict)
    log_line  = pyqtSignal(str)
    finished  = pyqtSignal(dict)

    def __init__(self, paths):
        super().__init__()
        self.paths = paths
        self._proc = None
        self._paused = False
        self._stopped = False

    def pause(self):
        if self._proc and not self._paused:
            try:
                os.kill(self._proc.pid, signal.SIGSTOP)
                self._paused = True
            except Exception:
                pass

    def resume(self):
        if self._proc and self._paused:
            try:
                os.kill(self._proc.pid, signal.SIGCONT)
                self._paused = False
            except Exception:
                pass

    def stop(self):
        self._stopped = True
        if self._paused:
            self.resume()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self):
        if not clamscan_available():
            self.log_line.emit("ERROR: clamscan not found. Install with: sudo apt install clamav")
            self.finished.emit({"scanned": 0, "threats": 0, "errors": 1})
            return

        total = count_files(self.paths)
        if total == 0:
            self.finished.emit({"scanned": 0, "threats": 0, "errors": 0})
            return

        self.log_line.emit(f"ClamAV scan starting — {total} files across {len(self.paths)} target(s)")

        cmd = ["clamscan", "--recursive", "--no-summary"] + self.paths
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log_line.emit(f"ERROR launching clamscan: {e}")
            self.finished.emit({"scanned": 0, "threats": 0, "errors": 1})
            return

        scanned = threats = errors = 0

        for line in self._proc.stdout:
            if self._stopped:
                break
            line = line.strip()
            if not line or ": " not in line:
                continue

            filepath, rest = line.split(": ", 1)
            rest = rest.strip()

            if rest == "OK":
                scanned += 1
                result = {"path": filepath, "status": "Clean", "threat": "—", "size": self._filesize(filepath)}
                self.log_line.emit(f"Clean: {filepath}")
            elif rest.endswith(" FOUND"):
                threat_name = rest[:-6].strip()
                scanned += 1; threats += 1
                result = {"path": filepath, "status": "Threat", "threat": threat_name, "size": self._filesize(filepath)}
                self.log_line.emit(f"THREAT: {filepath} — {threat_name}")
            elif "ERROR" in rest:
                errors += 1
                result = {"path": filepath, "status": "Error", "threat": rest, "size": 0}
                self.log_line.emit(f"Error: {filepath} — {rest}")
            else:
                continue

            self.file_done.emit(result)
            self.progress.emit(scanned, total)

        self._proc.wait()
        self.finished.emit({"scanned": scanned, "threats": threats, "errors": errors})

    def _filesize(self, path):
        try:
            return os.path.getsize(path)
        except Exception:
            return 0


# ── Reusable widgets ─────────────────────────────────────────────────────────
def card(parent=None):
    w = QFrame(parent)
    w.setStyleSheet(f"QFrame {{ background: {BG_CARD}; border: none; border-radius: 12px; }}")
    return w


def label(text, size=13, weight="normal", color=TEXT_PRI, mono=False):
    l = QLabel(text)
    font = QFont("Consolas" if mono else "Segoe UI", size)
    if weight == "bold":
        font.setBold(True)
    elif weight == "semibold":
        font.setWeight(QFont.DemiBold)
    l.setFont(font)
    l.setStyleSheet(f"color: {color}; background: transparent;")
    return l


def btn(text, primary=False, danger=False, small=False):
    b = QPushButton(text)
    fs = 11 if small else 13
    if primary:
        bg, hover = ACCENT, ""
    elif danger:
        bg, hover = "", RED
    else:
        bg, hover = BG_CARD, "#1e293b"

    b.setStyleSheet(f"""
        QPushButton {{
            background: {bg}; color: {TEXT_PRI}; border: none;
            border-radius: 8px; font-size: {fs}px; font-weight: 600;
        }}
        QPushButton:hover {{ background: {hover}; border-color: {ACCENT if primary else BORDER}; }}
        QPushButton:pressed {{ background: {hover}; }}
        QPushButton:disabled {{ background: {BG_DARK}; color: {TEXT_MUT}; }}
    """)
    return b


class KpiCard(QFrame):
    def __init__(self, title, value, sub, icon, color=ACCENT):
        super().__init__()
        self.color = color
        self.setStyleSheet(f"QFrame {{ background: {BG_CARD}; border: none; border-radius: 12px; }}")
        lay = QVBoxLayout(self)
        # Flush margins — numbers and text sit clean without boxy spacing
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(0)
        lbl_title = label(title, 10, color=TEXT_SEC)
        lbl_title.setStyleSheet(f"color: {TEXT_SEC}; letter-spacing: 1px; background: transparent;")
        top.addWidget(lbl_title)
        top.addStretch()
        ico = label(icon, 16)
        ico.setStyleSheet(f"color: {color}; background: transparent;")
        top.addWidget(ico)
        lay.addLayout(top)

        self.val_label = label(value, 28, "bold")
        self.val_label.setStyleSheet(f"color: {TEXT_PRI}; background: transparent; letter-spacing: -1px;")
        lay.addWidget(self.val_label)
        lay.addWidget(label(sub, 11, color=TEXT_SEC))

    def set_value(self, v):
        self.val_label.setText(str(v))


class ScanBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"background: {BG_CARD}; border: none; border-radius: 10px;")
        self._start_time = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)

        row = QHBoxLayout()
        self.lbl_file = label("No scan running", 11, color=TEXT_SEC)
        row.addWidget(self.lbl_file)
        row.addStretch()
        self.lbl_pct = label("—", 11, color=ACCENT, mono=True)
        row.addWidget(self.lbl_pct)
        lay.addLayout(row)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(4)
        self.bar.setStyleSheet(f"""
            QProgressBar {{ background: {BG_DARK}; border-radius: 2px; }}
            QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {ACCENT}, stop:1 {ACCENT2}); border-radius: 2px; }}
        """)
        lay.addWidget(self.bar)

        self.lbl_eta = label("", 10, color=TEXT_SEC)
        lay.addWidget(self.lbl_eta)

    def start(self):
        self._start_time = time.time()
        self.lbl_eta.setText("Estimating time…")

    def update(self, current, total):
        pct = int(current / total * 100) if total else 0
        self.bar.setValue(pct)
        self.lbl_pct.setText(f"{pct}%")
        self.lbl_file.setText(f"Scanning file {current} of {total}")
        if self._start_time and current > 0:
            elapsed = time.time() - self._start_time
            rate = current / elapsed
            remaining = (total - current) / rate if rate > 0 else 0
            self.lbl_eta.setText(f"Est. time remaining: {self._fmt(remaining)}")

    def _fmt(self, secs):
        secs = int(secs)
        if secs < 60: return f"{secs}s"
        elif secs < 3600:
            m, s = divmod(secs, 60); return f"{m}m {s}s"
        else:
            h, rem = divmod(secs, 3600); m, s = divmod(rem, 60); return f"{h}h {m}m {s}s"

    def reset(self, msg="No scan running"):
        self._start_time = None
        self.bar.setValue(0)
        self.lbl_pct.setText("—")
        self.lbl_file.setText(msg)
        self.lbl_eta.setText("")


# ── Sidebar nav ──────────────────────────────────────────────────────────────
class NavItem(QWidget):
    clicked = pyqtSignal()

    def __init__(self, icon, text, active=False):
        super().__init__()
        self._active = active
        self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(8)
        self.ico = label(icon, 14)
        lay.addWidget(self.ico)
        self.lbl = label(text, 13)
        lay.addWidget(self.lbl)
        lay.addStretch()
        self._refresh()

    def _refresh(self):
        bg = BORDER if self._active else "transparent"
        self.setStyleSheet(f"background: {bg}; border-radius: 8px;")
        self.lbl.setStyleSheet(f"color: {TEXT_PRI if self._active else TEXT_SEC}; background: transparent;")

    def set_active(self, v):
        self._active = v
        self._refresh()

    def mousePressEvent(self, _):
        self.clicked.emit()


# ── Main window ──────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ClamAV Web UI Client")
        self.resize(1200, 760)
        self.setMinimumSize(900, 600)
        self.setStyleSheet(STYLE)

        self.worker = None
        self.scan_results = []
        self.kpi_scanned = 0
        self.kpi_threats  = 0
        self.kpi_clean    = 0
        self._paused      = False

        self._build_ui()
        self._start_clock()
        self._refresh_last_scan_ui()
        self._load_quarantine_from_manifest()

    def _load_quarantine_from_manifest(self):
        """Populate the quarantine table from disk manifest on startup."""
        manifest = _load_manifest()
        for safe_name, info in manifest.items():
            q_path = os.path.join(QUARANTINE_DIR, safe_name)
            if os.path.exists(q_path):
                self._add_quarantine_row(
                    info["original"], info["threat"], info["date"], safe_name
                )
        if self.q_table.rowCount() > 0:
            self.q_empty.setVisible(False)

    def _build_ui(self):
        root = QWidget()
        root_lay = QHBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)
        self.setCentralWidget(root)

        sidebar = self._build_sidebar()
        root_lay.addWidget(sidebar)

        div = QFrame()
        div.setFixedWidth(1)
        div.setStyleSheet(f"background: {BORDER};")
        root_lay.addWidget(div)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_dashboard())
        self.stack.addWidget(self._page_scan())
        self.stack.addWidget(self._page_quarantine())
        self.stack.addWidget(self._page_logs())
        root_lay.addWidget(self.stack, 1)

    def _build_sidebar(self):
        side = QFrame()
        side.setFixedWidth(210)
        side.setStyleSheet(f"background: {BG_SIDE}; border: none;")
        lay = QVBoxLayout(side)
        lay.setContentsMargins(12, 0, 12, 12)
        lay.setSpacing(2)

        logo_frame = QFrame()
        logo_frame.setFixedHeight(56)
        logo_frame.setStyleSheet("border-bottom: 1px solid #1e293b; background: transparent;")
        ll = QHBoxLayout(logo_frame)
        ll.setContentsMargins(4, 0, 0, 0)
        ll.setSpacing(1)
        name_col = QVBoxLayout()
        name_col.setSpacing(0)
        name_col.addWidget(label("ClamAV Web UI Client"))
        ll.addLayout(name_col)
        lay.addWidget(logo_frame)
        lay.addSpacing(8)

        nav_data = [
            ("⊞", "Dashboard", 0),
            ("⌕", "Scan Files", 1),
            ("⊘", "Quarantine", 2),
            ("☰", "Logs", 3),
        ]
        self.nav_items = []
        for ico, txt, idx in nav_data:
            item = NavItem(ico, txt, active=(idx == 0))
            item.clicked.connect(lambda i=idx: self._switch_page(i))
            self.nav_items.append(item)
            lay.addWidget(item)

        lay.addStretch()

        self.status_card = QFrame()
        sl = QVBoxLayout(self.status_card)
        sl.setSpacing(3)
        self.status_dot = label("● Protected", 12, "semibold", GREEN)
        sl.addWidget(self.status_dot)
        self.status_sub = label("Last scan: checking…", 10, color=TEXT_SEC)
        sl.addWidget(self.status_sub)
        self.warn_label = label("⚠ No scan in over a week!", 10, color=YELLOW)
        self.warn_label.setVisible(False)
        sl.addWidget(self.warn_label)
        lay.addWidget(self.status_card)

        return side

    def _switch_page(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, item in enumerate(self.nav_items):
            item.set_active(i == idx)

    # ── Dashboard page ───────────────────────────────────────────────────────
    def _page_dashboard(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 18, 24, 18)
        lay.setSpacing(14)

        hdr = QHBoxLayout()
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(label("Security Overview", 20, "bold"))
        self.lbl_time = label("", 11, color=TEXT_SEC)
        col.addWidget(self.lbl_time)
        hdr.addLayout(col)
        hdr.addStretch()
        quick_scan = btn("▶  Quick Scan", primary=True)
        quick_scan.clicked.connect(lambda: self._quick_scan())
        hdr.addWidget(quick_scan)
        lay.addLayout(hdr)

        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.kpi_total   = KpiCard("FILES SCANNED", "0",  "total scanned",   "📁", ACCENT)
        self.kpi_threat  = KpiCard("THREATS FOUND", "0",  "items flagged",   "⚠", RED)
        self.kpi_clean2  = KpiCard("CLEAN FILES",   "0",  "no issues found", "✓", GREEN)
        self.kpi_quarant = KpiCard("QUARANTINED",   "0",  "isolated items",  "⊘", YELLOW)
        for k in [self.kpi_total, self.kpi_threat, self.kpi_clean2, self.kpi_quarant]:
            kpi_row.addWidget(k)
        lay.addLayout(kpi_row)

        self.dash_bar = ScanBar()
        lay.addWidget(self.dash_bar)

        lay.addWidget(label("Recent Detections", 13, "semibold"))
        self.dash_table = self._make_results_table()
        lay.addWidget(self.dash_table, 1)

        return page

    # ── Scan page ────────────────────────────────────────────────────────────
    def _page_scan(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 18, 24, 18)
        lay.setSpacing(14)

        lay.addWidget(label("Scan Files & Folders", 20, "bold"))

        drop = QFrame()
        drop.setFixedHeight(100)
        drop.setStyleSheet(f"""
            QFrame {{
                background: {BG_CARD}; border: 2px dashed {BORDER};
                border-radius: 14px;
            }}
        """)
        dl = QHBoxLayout(drop)
        dl.setAlignment(Qt.AlignCenter)
        dl.setSpacing(16)

        for ico, txt, fn in [
            ("📄", "Add Files", self._choose_files),
            ("📁", "Add Folder", self._choose_folder),
        ]:
            b = QPushButton(f"{ico}  {txt}")
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedWidth(150)
            b.setStyleSheet(f"""
                QPushButton {{
                    background: {BG_DARK}; color: {TEXT_PRI}; border: none;
                    border-radius: 8px; font-size: 13px; font-weight: 600;
                }}
                QPushButton:hover {{ background: {BORDER}; }}
            """)
            b.clicked.connect(fn)
            dl.addWidget(b)

        lay.addWidget(drop)

        self.path_list = QListWidget()
        self.path_list.setFixedHeight(90)
        self.path_list.setStyleSheet(f"background: {BG_CARD}; border: none; border-radius: 8px;")
        lay.addWidget(self.path_list)

        btn_row = QHBoxLayout()
        self.btn_clear = btn("🗑  Clear List", danger=True)
        self.btn_start = btn("▶  Start Scan", primary=True)
        self.btn_pause = btn("⏸  Pause")
        self.btn_stop  = btn("■  Stop")
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.btn_clear.clicked.connect(self._clear_paths)
        self.btn_start.clicked.connect(self._start_scan)
        self.btn_pause.clicked.connect(self._toggle_pause)
        self.btn_stop.clicked.connect(self._stop_scan)
        btn_row.addWidget(self.btn_clear)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_stop)
        btn_row.addWidget(self.btn_pause)
        btn_row.addWidget(self.btn_start)
        lay.addLayout(btn_row)

        self.scan_bar = ScanBar()
        lay.addWidget(self.scan_bar)

        lay.addWidget(label("Scan Results", 13, "semibold"))
        self.scan_table = self._make_results_table()
        lay.addWidget(self.scan_table, 1)

        return page

    # ── Quarantine page ──────────────────────────────────────────────────────
    def _page_quarantine(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 18, 24, 18)
        lay.setSpacing(14)

        hdr = QHBoxLayout()
        hdr.addWidget(label("Quarantine", 20, "bold"))
        hdr.addStretch()
        clr = btn("🗑  Clear All", danger=True, small=True)
        clr.clicked.connect(self._clear_quarantine)
        hdr.addWidget(clr)
        lay.addLayout(hdr)

        self.q_table = QTableWidget(0, 5)
        self.q_table.setHorizontalHeaderLabels(["ORIGINAL PATH", "THREAT", "DATE", "RESTORE", "DELETE"])
        self.q_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.q_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.q_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.q_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.q_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.q_table.verticalHeader().setVisible(False)
        self.q_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.q_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.q_table.setShowGrid(True)
        self.q_table.verticalHeader().setDefaultSectionSize(36)
        lay.addWidget(self.q_table, 1)

        self.q_empty = label("No quarantined items. Threats found during a scan will appear here.", 12, color=TEXT_SEC)
        self.q_empty.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.q_empty)

        return page

    # ── Logs page ────────────────────────────────────────────────────────────
    def _page_logs(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 18, 24, 18)
        lay.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(label("Activity Log", 20, "bold"))
        hdr.addStretch()
        clr = btn("Clear Log", small=True)
        clr.clicked.connect(self._clear_log)
        hdr.addWidget(clr)
        lay.addLayout(hdr)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        lay.addWidget(self.log_box, 1)

        self._log("ClamAV Web UI Client started.")
        if clamscan_available():
            self._log("ClamAV detected — real scanning enabled.")
        else:
            self._log("WARNING: clamscan not found. Install with: sudo apt install clamav")
        return page

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _make_results_table(self):
        t = QTableWidget(0, 4)
        t.setHorizontalHeaderLabels(["FILE", "STATUS", "THREAT", "SIZE"])
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        t.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        t.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        t.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Tighter row height — no bloated cell boxing
        t.verticalHeader().setDefaultSectionSize(28)
        return t

    def _add_result_row(self, table, result):
        row = table.rowCount()
        table.insertRow(row)

        fname = QTableWidgetItem(os.path.basename(result["path"]))
        fname.setToolTip(result["path"])
        table.setItem(row, 0, fname)

        status_item = QTableWidgetItem(result["status"])
        color = GREEN if result["status"] == "Clean" else RED if result["status"] == "Threat" else YELLOW
        status_item.setForeground(QColor(color))
        table.setItem(row, 1, status_item)
        table.setItem(row, 2, QTableWidgetItem(result["threat"]))

        size = result["size"]
        if size < 1024:       size_str = f"{size} B"
        elif size < 1024**2:  size_str = f"{size/1024:.1f} KB"
        else:                 size_str = f"{size/1024**2:.1f} MB"
        table.setItem(row, 3, QTableWidgetItem(size_str))

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{ts}]  {msg}")

    def _clear_log(self):
        self.log_box.clear()

    def _clear_quarantine(self):
        if self.q_table.rowCount() == 0:
            return
        reply = QMessageBox.warning(
            self, "Delete All Quarantined Files",
            "This will permanently delete ALL quarantined files from disk.\nThis cannot be undone.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.Cancel
        )
        if reply != QMessageBox.Yes:
            return
        manifest = _load_manifest()
        failed = []
        for safe_name in list(manifest.keys()):
            ok, msg = delete_quarantined(safe_name)
            if not ok:
                failed.append(f"{safe_name}: {msg}")
        self.q_table.setRowCount(0)
        self.q_empty.setVisible(True)
        self._update_kpis()
        if failed:
            QMessageBox.warning(self, "Some deletions failed", "\n".join(failed))
            self._log(f"Clear quarantine: {len(failed)} error(s).")
        else:
            self._log("All quarantined files permanently deleted.")

    def _start_clock(self):
        self._tick()
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(60000)

    def _tick(self):
        now = datetime.now().strftime("%A, %d %B %Y  ·  %H:%M")
        self.lbl_time.setText(now)

    def _choose_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in files:
            if not self._path_exists(f):
                self.path_list.addItem(f)

    def _choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder and not self._path_exists(folder):
            self.path_list.addItem(folder)

    def _path_exists(self, p):
        for i in range(self.path_list.count()):
            if self.path_list.item(i).text() == p:
                return True
        return False

    def _clear_paths(self):
        self.path_list.clear()

    def _get_paths(self):
        return [self.path_list.item(i).text() for i in range(self.path_list.count())]

    def _refresh_last_scan_ui(self):
        _, label_str, days = load_last_scan()
        self.status_sub.setText(f"Last scan: {label_str}")

        if days >= 7:
            self.status_card.setStyleSheet
               # f"background: #2d1a00; border: 1px solid {YELLOW};"
            self.status_dot.setText("● Scan Overdue")
            self.status_dot.setStyleSheet(f"color: {YELLOW}; background: transparent;")
            self.warn_label.setVisible(True)
        elif days == 9999:
            self.status_card.setStyleSheet
               # f"background: #2d1a00; border: 1px solid {YELLOW};"
            self.status_dot.setText("● Never Scanned")
            self.status_dot.setStyleSheet(f"color: {YELLOW}; background: transparent;")
            self.warn_label.setVisible(True)
        else:
            self.status_card.setStyleSheet
             #   f"background: #052e16; border: 1px solid #166534;"
            self.status_dot.setText("● Protected")
            self.status_dot.setStyleSheet(f"color: {GREEN}; background: transparent;")
            self.warn_label.setVisible(False)

    def _quick_scan(self):
        home = Path.home()
        targets = [str(home / "Desktop"), str(home / "Downloads")]
        targets = [t for t in targets if os.path.isdir(t)]
        if not targets:
            QMessageBox.information(self, "Quick Scan", "Could not find Desktop or Downloads folder.")
            return
        self.path_list.clear()
        for t in targets:
            self.path_list.addItem(t)
        self._switch_page(1)
        self._start_scan()

    def _start_scan(self):
        if not clamscan_available():
            QMessageBox.critical(self, "ClamAV Not Found",
                "clamscan is not installed.\n\nInstall it with:\n  sudo apt install clamav\n\nThen update definitions:\n  sudo freshclam")
            return

        paths = self._get_paths()
        if not paths:
            QMessageBox.information(self, "No Target", "Please add files or folders to scan.")
            return

        self.scan_table.setRowCount(0)
        self.dash_table.setRowCount(0)
        self.kpi_scanned = self.kpi_threats = self.kpi_clean = 0
        self._update_kpis()
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_stop.setEnabled(True)
        self._paused = False

        self.worker = ScanWorker(paths)
        self.worker.progress.connect(self._on_progress)
        self.worker.file_done.connect(self._on_file_done)
        self.worker.log_line.connect(self._log)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()
        self.scan_bar.start()
        self.dash_bar.start()
        self._log(f"Scan started — {len(paths)} target(s)")
        self.status_card.setStyleSheet(
            f"background: #0c1a3d; border: 1px solid {ACCENT}; border-radius: 10px;")
        self.status_dot.setText("● Scanning…")
        self.status_dot.setStyleSheet(f"color: {ACCENT}; background: transparent;")
        self.warn_label.setVisible(False)

    def _toggle_pause(self):
        if not self.worker:
            return
        if not self._paused:
            self.worker.pause()
            self._paused = True
            self.btn_pause.setText("▶  Resume")
            self.scan_bar.lbl_file.setText("Scan paused…")
            self.scan_bar.lbl_eta.setText("")
            self.status_dot.setText("● Paused")
            self.status_dot.setStyleSheet(f"color: {YELLOW}; background: transparent;")
            self.status_card.setStyleSheet(
                f"background: #2d1a00; border: 1px solid {YELLOW}; border-radius: 10px;")
            self._log("Scan paused.")
        else:
            self.worker.resume()
            self._paused = False
            self.btn_pause.setText("⏸  Pause")
            self.status_dot.setText("● Scanning…")
            self.status_dot.setStyleSheet(f"color: {ACCENT}; background: transparent;")
            self.status_card.setStyleSheet(
                f"background: #0c1a3d; border: 1px solid {ACCENT}; border-radius: 10px;")
            self._log("Scan resumed.")

    def _stop_scan(self):
        if self.worker:
            self.worker.stop()
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸  Pause")
        self._paused = False
        self._log("Scan stopped by user.")

    def _on_progress(self, current, total):
        self.scan_bar.update(current, total)
        self.dash_bar.update(current, total)

    def _on_file_done(self, result):
        self.kpi_scanned += 1
        if result["status"] == "Threat":
            self.kpi_threats += 1
            # Actually move the file to quarantine and lock it
            q_path, safe_name = quarantine_file(result["path"], result["threat"])
            if q_path:
                self._log(f"Quarantined: {result['path']} → {q_path}")
                self._add_quarantine_row(result["path"], result["threat"],
                                         datetime.now().strftime("%Y-%m-%d %H:%M"), safe_name)
                self.q_empty.setVisible(False)
            else:
                self._log(f"WARNING: Could not quarantine {result['path']} — {safe_name}")
        else:
            self.kpi_clean += 1

        self._add_result_row(self.scan_table, result)
        if result["status"] == "Threat":
            self._add_result_row(self.dash_table, result)
        self._update_kpis()

    def _add_quarantine_row(self, original_path, threat, date, safe_name):
        r = self.q_table.rowCount()
        self.q_table.insertRow(r)

        path_item = QTableWidgetItem(original_path)
        path_item.setToolTip(original_path)
        self.q_table.setItem(r, 0, path_item)

        t_item = QTableWidgetItem(threat)
        t_item.setForeground(QColor(RED))
        self.q_table.setItem(r, 1, t_item)
        self.q_table.setItem(r, 2, QTableWidgetItem(date))

        # Restore button
        restore_btn = QPushButton("↩ Restore")
        restore_btn.setCursor(Qt.PointingHandCursor)
        restore_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1e3a5f; color: {TEXT_PRI}; border: none;
                border-radius: 6px; font-size: 11px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {ACCENT}; }}
        """)
        restore_btn.clicked.connect(lambda _, sn=safe_name, row=r: self._restore_item(sn))
        self.q_table.setCellWidget(r, 3, restore_btn)

        # Delete button
        del_btn = QPushButton("🗑 Delete")
        del_btn.setCursor(Qt.PointingHandCursor)
        del_btn.setStyleSheet(f"""
            QPushButton {{
                background: #3b0f0f; color: {TEXT_PRI}; border: none;
                border-radius: 6px; font-size: 11px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {RED}; }}
        """)
        del_btn.clicked.connect(lambda _, sn=safe_name: self._delete_item(sn))
        self.q_table.setCellWidget(r, 4, del_btn)

    def _find_quarantine_row(self, safe_name):
        """Find row index by matching safe_name stored in the restore button."""
        for r in range(self.q_table.rowCount()):
            rb = self.q_table.cellWidget(r, 3)
            if rb and hasattr(rb, '_safe_name') and rb._safe_name == safe_name:
                return r
        # fallback: scan path column via manifest
        manifest = _load_manifest()
        if safe_name in manifest:
            orig = manifest[safe_name]["original"]
            for r in range(self.q_table.rowCount()):
                item = self.q_table.item(r, 0)
                if item and item.text() == orig:
                    return r
        return -1

    def _restore_item(self, safe_name):
        reply = QMessageBox.question(
            self, "Restore File",
            "Restore this file to its original location?\n\nThe file was flagged as a threat — only restore if you're sure it's safe.",
            QMessageBox.Yes | QMessageBox.Cancel
        )
        if reply != QMessageBox.Yes:
            return
        ok, msg = restore_file(safe_name)
        if ok:
            self._log(f"Restored: {msg}")
            self._remove_quarantine_row_by_safe_name(safe_name)
        else:
            QMessageBox.critical(self, "Restore Failed", f"Could not restore file:\n{msg}")
            self._log(f"Restore failed: {msg}")

    def _delete_item(self, safe_name):
        reply = QMessageBox.warning(
            self, "Permanently Delete",
            "This will permanently delete the file from disk.\nThis cannot be undone.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.Cancel
        )
        if reply != QMessageBox.Yes:
            return
        ok, msg = delete_quarantined(safe_name)
        if ok:
            self._log(f"Permanently deleted quarantined file ({safe_name}).")
            self._remove_quarantine_row_by_safe_name(safe_name)
        else:
            QMessageBox.critical(self, "Delete Failed", f"Could not delete file:\n{msg}")
            self._log(f"Delete failed: {msg}")

    def _remove_quarantine_row_by_safe_name(self, safe_name):
        """Remove the table row matching this safe_name by checking the manifest original path."""
        manifest = _load_manifest()
        orig = manifest.get(safe_name, {}).get("original", "")
        for r in range(self.q_table.rowCount()):
            item = self.q_table.item(r, 0)
            if item and item.text() == orig:
                self.q_table.removeRow(r)
                break
        else:
            # If manifest already updated (already removed), just remove by index scan of path
            pass
        if self.q_table.rowCount() == 0:
            self.q_empty.setVisible(True)
        self._update_kpis()

    def _on_finished(self, summary):
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸  Pause")
        self.btn_stop.setEnabled(False)
        self._paused = False
        self.scan_bar.reset("Scan complete")
        self.dash_bar.reset("Scan complete")
        save_last_scan()
        self._refresh_last_scan_ui()
        self._log(
            f"Scan complete — {summary['scanned']} files scanned, "
            f"{summary['threats']} threat(s) found, {summary['errors']} error(s)"
        )

    def _update_kpis(self):
        self.kpi_total.set_value(self.kpi_scanned)
        self.kpi_threat.set_value(self.kpi_threats)
        self.kpi_clean2.set_value(self.kpi_clean)
        self.kpi_quarant.set_value(self.kpi_threats)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
