#!/usr/bin/env python3
"""
Defender PC Guard  -  merged application
=========================================
Combines two apps into one clean, themed GUI:

  * Windows Defender Updater  -  check and update Microsoft Defender
    (definitions + optional scanning engine), compare what's installed
    against the latest Microsoft publishes online.

  * PC Guard  -  a Defender companion watchdog. It does not try to be an
    antivirus; it watches the things Defender is weakest on:
       1. Persistence  - what starts automatically (Run keys, Startup folder,
                          Services, Scheduled Tasks). Alerts on any change.
       2. Tamper       - the hosts file, DNS servers, and Defender's own
                          settings (exclusions / real-time protection).
       3. Outbound     - which processes are talking to the network, flagging
                          any NEW process -> remote-address pair.

Includes a light AND a dark theme (toggle in the footer).

Standard library only (tkinter). Optional: pystray + Pillow for the tray icon.
Windows high-DPI aware.
"""

import ctypes
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import winreg
except Exception:  # only on Windows
    winreg = None

try:
    import winsound
except Exception:  # non-Windows
    winsound = None

try:
    import pystray
    from pystray import Menu, MenuItem
    from PIL import Image
    HAS_TRAY = True
except Exception:  # tray is optional; app still works without it
    HAS_TRAY = False

# Current version - bump whenever the app is updated.
APP_VERSION = "2.0.1"

APP_NAME = "Defender PC Guard"
APP_TAGLINE = "Windows Defender updater + companion watchdog."
APP_AUTHOR = "aJonyMous69"
APP_CODED_BY = "DeepSeek V4.1 Flash"
APP_REBUILD_BY = "Kimi (audit fixes)"
APP_COPYRIGHT_YEAR = "2026"

NO_WINDOW = 0x08000000  # subprocess CREATE_NO_WINDOW

DATA_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "PCGuard")
os.makedirs(DATA_DIR, exist_ok=True)
BASELINE_FILE = os.path.join(DATA_DIR, "baseline.json")
TRUSTED_FILE = os.path.join(DATA_DIR, "trusted_net.json")
IGNORED_FILE = os.path.join(DATA_DIR, "ignored_alerts.json")

RUN_VALUE_NAME = "PCGuard"          # HKCU Run key value name
BASELINE_AGE_DAYS = 30               # nudge to re-baseline after this many days
SYN_STUCK_SECS = 10.0                # SYN_SENT this long = "not answering"
LOG_MAX_BYTES = 2 * 1024 * 1024      # rotate the daily log past this size


# ----------------------------------------------------------------------------
# Metadata / about (same layout family as the other apps)
# ----------------------------------------------------------------------------
def about_text() -> str:
    lines = [f"{APP_NAME} {APP_VERSION}", "", APP_TAGLINE]
    if APP_AUTHOR:
        lines.append(f"Created by: {APP_AUTHOR}.")
    if APP_CODED_BY:
        lines.append(f"Coded by: {APP_CODED_BY}.")
    if APP_REBUILD_BY:
        lines.append(f"Rebuilt by: {APP_REBUILD_BY}.")
    if APP_COPYRIGHT_YEAR:
        lines.append(f"Copyright {APP_COPYRIGHT_YEAR}")
    return "\n".join(lines)


def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def about_icon(size=112):
    path = resource_path("icon.ico")
    if not os.path.isfile(path):
        return None
    try:
        from PIL import Image, ImageTk
        img = Image.open(path).convert("RGBA")
        img = img.resize((size, size), Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


def enable_hidpi():
    """Enable crisp, per-monitor-aware rendering BEFORE the Tk root is created."""
    try:
        import ctypes
        try:
            ctypes.windll.user32.SetProcessDpiAwarenessContext(
                ctypes.c_void_p(-4))  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        except Exception:
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


# ============================================================================
# Backend: Windows Defender update (from the original Defender Updater app)
# ============================================================================
def run_ps_full(script, timeout=120):
    """Run a PowerShell command and return (returncode, stdout, stderr).
    Uses CREATE_NO_WINDOW on Windows so no console window pops up."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(
        ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
        creationflags=flags, encoding="utf-8", errors="replace",
    )
    return p.returncode, p.stdout, p.stderr


def def_is_admin():
    try:
        rc, out, err = run_ps_full(
            "([Security.Principal.WindowsPrincipal]"
            "[Security.Principal.WindowsIdentity]::GetCurrent())."
            "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            timeout=30,
        )
        return out.strip() == "True"
    except Exception:
        return False


def date_from_ms(txt):
    """Convert '/Date(1789360477000)/' into a readable local date/time."""
    try:
        ms = int(re.search(r"(\d+)", txt).group(1))
        return datetime.fromtimestamp(ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return txt


def get_local_status():
    """Return installed Defender info as a dict."""
    script = (
        "Get-MpComputerStatus | Select-Object "
        "AntivirusSignatureVersion,AntivirusSignatureLastUpdated,"
        "AMEngineVersion,AMProductVersion,RealTimeProtectionEnabled "
        "| ConvertTo-Json"
    )
    rc, out, err = run_ps_full(script, timeout=60)
    if rc != 0 or not out.strip():
        raise RuntimeError(err.strip() or "Could not read Defender status.")
    d = json.loads(out)
    return {
        "sig_version": d.get("AntivirusSignatureVersion"),
        "sig_date": date_from_ms(d.get("AntivirusSignatureLastUpdated", "")),
        "engine": d.get("AMEngineVersion"),
        "product": d.get("AMProductVersion"),
        "rt": bool(d.get("RealTimeProtectionEnabled")),
    }


def fetch_text(url, timeout=25):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def get_latest_online():
    """Return Microsoft's latest published versions as a dict."""
    html = fetch_text("https://www.microsoft.com/en-us/wdsi/defenderupdates")

    def grab(pat):
        m = re.search(pat, html)
        return m.group(1).strip() if m else None

    latest = {
        "version": grab(r"Version: <span>([0-9.]+)</span>"),
        "engine": grab(r"Engine Version: <span>([0-9.]+)</span>"),
        "platform": grab(r"Platform Version: <span>([0-9.]+)</span>"),
        "released": grab(r'Released: <span id="dateofrelease">([^<]+)</span>'),
    }
    if not latest["version"] or not latest["engine"]:
        raise RuntimeError(
            "Could not read version numbers from the Microsoft page (layout may have changed)."
        )
    return latest


def compare_versions(a, b):
    """Return -1 if a < b, 0 if equal, 1 if a > b (numeric dotted compare).
    Tolerates None / non-string input (missing Defender fields) as '0'."""
    a = str(a or "0")
    b = str(b or "0")
    pa = [int(x) for x in re.split(r"[.\-]", a) if x.strip().isdigit()]
    pb = [int(x) for x in re.split(r"[.\-]", b) if x.strip().isdigit()]
    n = max(len(pa), len(pb))
    for i in range(n):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return -1
        if va > vb:
            return 1
    return 0


# ============================================================================
# Backend: PC Guard collectors / OS helpers
# ============================================================================
def run_cmd(args, timeout=25):
    """Run a command, return stdout text (empty on failure)."""
    try:
        cp = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW)
        return cp.stdout or ""
    except Exception:
        return ""


def run_ps(script, timeout=25):
    """Run a PowerShell snippet, return stdout text (for collectors)."""
    return run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout)


def _json(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


RUN_KEYS = []


def _init_run_keys():
    if winreg is None:
        return []
    hkcu, hklm = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
    return [
        ("HKCU", hkcu, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", hkcu, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", hklm, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", hklm, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", hklm,
         r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]


RUN_KEYS = _init_run_keys()


def collect_run_entries():
    out = {}
    for hive_name, hive, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
        except Exception:
            continue
        try:  # always close the key - this runs every monitor cycle
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
                except Exception:
                    break
                out[f"{hive_name}\\{name}"] = str(val)
        finally:
            winreg.CloseKey(key)
    return out


def collect_startup_files():
    out = {}
    folders = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("ProgramData", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for fd in folders:
        try:
            for n in os.listdir(fd):
                p = os.path.join(fd, n)
                if os.path.isfile(p):
                    out[p] = str(os.path.getsize(p))
        except Exception:
            pass
    return out


def collect_services():
    out = {}
    if winreg is None:
        return out
    try:
        root = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except Exception:
        return out
    try:  # close every key - this runs every monitor cycle (hundreds of
          # handles per pass, so leaking them adds up fast)
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break
            except Exception:
                break
            try:
                with winreg.OpenKey(root, name) as sk:
                    try:
                        img, _ = winreg.QueryValueEx(sk, "ImagePath")
                    except Exception:
                        img = ""
                    out[name] = str(img)
            except Exception:
                pass
    finally:
        winreg.CloseKey(root)
    return out


def collect_tasks():
    out = {}
    txt = run_cmd(["schtasks", "/query", "/fo", "csv", "/nh"], timeout=25)
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln.startswith('"'):
            continue
        bits = ln.split('","')
        if len(bits) >= 3:
            name = bits[0].strip('"')
            status = bits[2].strip('"')
            out[name] = status
    return out


def collect_defender_status():
    ps = ("Get-MpComputerStatus | Select-Object AntivirusEnabled,"
          "RealTimeProtectionEnabled,BehaviorMonitorEnabled,"
          "IoavProtectionEnabled,AntispywareEnabled,"
          "AntivirusSignatureVersion,AMServiceEnabled,"
          "@{n='AntivirusSignatureLastUpdated';e={"
          "if($_.AntivirusSignatureLastUpdated){"
          "$_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')}"
          "else{''}}} | ConvertTo-Json -Compress")
    return _json(run_ps(ps)) or {}


def collect_defender_prefs():
    ps = ("Get-MpPreference | Select-Object DisableRealtimeMonitoring,"
          "EnableControlledFolderAccess,ExclusionPath,ExclusionExtension,"
          "ExclusionProcess | ConvertTo-Json -Compress")
    return _json(run_ps(ps)) or {}


HOSTS_PATH = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "drivers", "etc", "hosts")


def hosts_hash():
    try:
        with open(HOSTS_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def collect_dns():
    ps = ("Get-DnsClientServerAddress -AddressFamily IPv4 | "
          "Select-Object InterfaceAlias,ServerAddresses | "
          "ConvertTo-Json -Compress")
    data = _json(run_ps(ps))
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for row in data:
        try:
            alias = row.get("InterfaceAlias", "")
            servers = row.get("ServerAddresses") or []
            if servers:
                out.append(f"{alias}: {', '.join(servers)}")
        except Exception:
            pass
    return sorted(out)


def collect_connections():
    txt = run_cmd(["netstat", "-ano"], timeout=20)
    pid_names = collect_pid_names()
    rows = []
    for ln in txt.splitlines():
        parts = ln.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        if parts[0] == "TCP":
            if len(parts) < 5:
                continue
            local, foreign, state, pid = parts[1], parts[2], parts[3], parts[4]
        else:  # UDP
            local, foreign, state, pid = parts[1], parts[2], "", parts[3]
        if state not in ("ESTABLISHED", "SYN_SENT"):
            continue
        # Strip IPv6 brackets so external IPv6 remotes are watched too
        # (previously every bracketed address was skipped, hiding all IPv6
        # outbound activity from the Network tab and the alerts).
        ip = foreign.rsplit(":", 1)[0].strip("[]")
        if (not ip or ip == "*" or ip.startswith("127.")
                or ip in ("0.0.0.0", "::", "::1")):
            continue
        rows.append({
            "pid": pid,
            "process": pid_names.get(pid, "?"),
            "remote": foreign,
            "ip": ip,
            "state": state,
        })
    seen = set()
    uniq = []
    for r in rows:
        k = (r["process"], r["ip"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    return uniq


_pid_cache = {"t": 0.0, "map": {}}


def collect_pid_names():
    now = time.time()
    if now - _pid_cache["t"] < 3 and _pid_cache["map"]:
        return _pid_cache["map"]
    txt = run_cmd(["tasklist", "/fo", "csv", "/nh"], timeout=20)
    m = {}
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln.startswith('"'):
            continue
        bits = ln.split('","')
        if len(bits) >= 2:
            name = bits[0].strip('"')
            pid = bits[1].strip('"')
            m[pid] = name
    _pid_cache["t"] = now
    _pid_cache["map"] = m
    return m


# ----------------------------------------------------------------------------
# Start with Windows (HKCU Run key - no admin needed, easy to undo)
# ----------------------------------------------------------------------------
def _startup_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --minimized'
    exe = sys.executable
    # Running from source: use pythonw.exe when it sits next to python.exe,
    # otherwise a console window flashes at every login.
    if os.path.basename(exe).lower() == "python.exe":
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(cand):
            exe = cand
    return f'"{exe}" "{os.path.abspath(__file__)}" --minimized'


def refresh_startup_minimized():
    if winreg is None:
        return
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            try:
                cur, _ = winreg.QueryValueEx(key, RUN_VALUE_NAME)
            except FileNotFoundError:
                return
            if "--minimized" not in cur and "--minimised" not in cur:
                winreg.SetValueEx(key, RUN_VALUE_NAME, 0, winreg.REG_SZ,
                                  cur.rstrip() + " --minimized")
    except Exception:
        pass


def startup_enabled():
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            try:
                winreg.QueryValueEx(key, RUN_VALUE_NAME)
                return True
            except FileNotFoundError:
                return False
    except Exception:
        return False


def set_startup(enable):
    if winreg is None:
        return False
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_SET_VALUE) as key:
            if enable:
                winreg.SetValueEx(key, RUN_VALUE_NAME, 0, winreg.REG_SZ,
                                  _startup_command())
            else:
                try:
                    winreg.DeleteValue(key, RUN_VALUE_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False


class TrayIcon:
    """Notification-area (system tray) icon for the main window."""

    def __init__(self, image_path, title, post):
        self.icon = None
        self._post = post
        if not HAS_TRAY:
            return
        try:
            image = Image.open(image_path)
            if max(image.size) > 64:
                image = image.resize((64, 64))
        except Exception:
            image = Image.new("RGB", (64, 64), (10, 122, 220))
        menu = Menu(
            MenuItem("Show " + APP_NAME, self._menu("show"), default=True),
            MenuItem("Take baseline snapshot", self._menu("baseline")),
            MenuItem("Scan now", self._menu("scan")),
            MenuItem("Start with Windows", self._menu("startup_toggle"),
                     checked=lambda item: startup_enabled()),
            Menu.SEPARATOR,
            MenuItem("Exit", self._menu("exit")),
        )
        try:
            self.icon = pystray.Icon("pcguard", image, title, menu)
            self.icon.run_detached()
        except Exception:
            self.icon = None

    def _menu(self, action):
        def handler(icon=None, item=None):
            self._post(action)
        return handler

    @property
    def available(self):
        return self.icon is not None

    def notify(self, message):
        if self.icon is not None:
            try:
                self.icon.notify(message, APP_NAME)
            except Exception:
                pass

    def stop(self):
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None


# ----------------------------------------------------------------------------
# Alert sound (non-blocking, rate-limited)
# ----------------------------------------------------------------------------
_alert_lock = threading.Lock()
_last_alert = [0.0]
ALERT_COOLDOWN = 2.0

ALERT_TONES = {
    "outbound": [(880, 160), (587, 260)],
    "tamper": [(1100, 130), (850, 130), (600, 250)],
}


def play_alert(kind="outbound"):
    if winsound is None:
        return
    now = time.monotonic()
    with _alert_lock:
        if now - _last_alert[0] < ALERT_COOLDOWN:
            return
        _last_alert[0] = now
    tones = ALERT_TONES.get(kind) or ALERT_TONES["outbound"]

    def _beep():
        try:
            for freq, dur in tones:
                winsound.Beep(freq, dur)
        except Exception:
            try:
                winsound.MessageBeep()
            except Exception:
                pass
    threading.Thread(target=_beep, daemon=True).start()


# ----------------------------------------------------------------------------
# Guard engine: snapshots, diffing, logging
# ----------------------------------------------------------------------------
class Guard:
    def __init__(self, emit, interval=8):
        self.emit = emit
        self.interval = interval
        self.baseline = {}
        self.trusted = set()
        self.seen_net = set()
        self._net_initialised = False
        self._running = False
        self._thread = None
        self.alert_count = 0
        self.ignored = set()
        self._net_burst = {}
        self._recent = {}
        self._syn_since = {}
        self._syn_alerted = set()
        self._change_seen = set()
        self.load()

    def load(self):
        self.baseline = _read_json(BASELINE_FILE) or {}
        t = _read_json(TRUSTED_FILE) or []
        self.trusted = set(tuple(x) for x in t)
        self.ignored = set(_read_json(IGNORED_FILE) or [])

    def save_ignored(self):
        _write_json(IGNORED_FILE, sorted(self.ignored))

    def save_baseline(self):
        _write_json(BASELINE_FILE, self.baseline)

    def save_trusted(self):
        _write_json(TRUSTED_FILE, [list(x) for x in sorted(self.trusted)])

    def _alert(self, text, kind="tamper"):
        if text in self.ignored:
            return
        self.alert_count += 1
        self.emit("alert", {"text": text, "kind": kind})

    def take_snapshot(self):
        self.emit("status", "Taking baseline snapshot...")
        snap = {
            "run": collect_run_entries(),
            "startup": collect_startup_files(),
            "services": collect_services(),
            "tasks": collect_tasks(),
            "hosts_hash": hosts_hash(),
            "dns": collect_dns(),
            "defprefs": collect_defender_prefs(),
            "saved_at": time.time(),
        }
        self.baseline = snap
        self._change_seen.clear()
        self.save_baseline()
        for c in collect_connections():
            self.seen_net.add((c["process"], c["ip"]))
        self._net_initialised = True
        self.emit("status", "Baseline saved.")
        self.emit("baseline", snap)
        return snap

    def check_persistence(self):
        if not self.baseline:
            return
        for label, fn, key in (
            ("Startup (registry)", collect_run_entries, "run"),
            ("Startup (folder)", collect_startup_files, "startup"),
            ("Service", collect_services, "services"),
            ("Scheduled task", collect_tasks, "tasks"),
        ):
            old = self.baseline.get(key, {})
            new = fn()
            for name in new:
                if name not in old:
                    sig = f"NEW|{key}|{name}|{new[name]}"
                    if sig in self._change_seen:
                        continue
                    self._change_seen.add(sig)
                    self._alert(f"NEW {label}: {name} = {new[name]}")
            for name in old:
                if name not in new:
                    sig = f"REM|{key}|{name}"
                    if sig in self._change_seen:
                        continue
                    self._change_seen.add(sig)
                    self._alert(f"REMOVED {label}: {name}")
            # Services included: a swapped service ImagePath is a classic
            # persistence move and must not slip through. Tasks are excluded
            # because their value is a volatile status (Ready/Running).
            if key in ("run", "startup", "services"):
                for name, val in new.items():
                    if name in old and old[name] != val:
                        sig = f"CHG|{key}|{name}|{val}"
                        if sig in self._change_seen:
                            continue
                        self._change_seen.add(sig)
                        self._alert(f"CHANGED {label}: {name} -> {val}")

    def check_tamper(self):
        if not self.baseline:
            return
        h = hosts_hash()
        if h and self.baseline.get("hosts_hash") and h != self.baseline["hosts_hash"]:
            self._alert("HOSTS FILE CHANGED (possible hijack).")
            self.baseline["hosts_hash"] = h
            self.save_baseline()
        dns = collect_dns()
        if self.baseline.get("dns") and dns and dns != self.baseline["dns"]:
            self._alert(f"DNS servers changed: {dns}")
            self.baseline["dns"] = dns
            self.save_baseline()
        prefs = collect_defender_prefs()
        old = self.baseline.get("defprefs", {})
        if prefs:
            def ex_all(p):
                items = []
                for k in ("ExclusionPath", "ExclusionExtension",
                          "ExclusionProcess"):
                    items.extend(str(x) for x in (p.get(k) or []))
                return items
            new_ex = ex_all(prefs)
            old_ex = ex_all(old)
            # Compare by content, not count: one exclusion swapped for
            # another must still alert, and we can say WHAT was added.
            added = [x for x in new_ex if x not in old_ex]
            if added:
                shown = ", ".join(added[:3]) + (
                    f" (+{len(added) - 3} more)" if len(added) > 3 else "")
                self._alert(
                    f"DEFENDER EXCLUSION ADDED: {shown}. Malware often "
                    f"adds these to hide. Review in Windows "
                    f"Security > Virus & threat protection.")
            if prefs.get("DisableRealtimeMonitoring") and not old.get(
                    "DisableRealtimeMonitoring"):
                self._alert(
                    "DEFENDER REAL-TIME PROTECTION WAS DISABLED!")
            # Only re-baseline (and hit the disk) when something changed -
            # this used to rewrite baseline.json every monitor cycle.
            if prefs != old:
                self.baseline["defprefs"] = prefs
                self.save_baseline()

    def check_defender(self):
        st = collect_defender_status()
        if st:
            self.emit("defender", st)

    RECENT_TTL = 300.0

    def check_network(self):
        conns = collect_connections()
        now = time.monotonic()
        current = set()
        for c in conns:
            key = (c["process"], c["ip"])
            current.add(key)
            stuck = False
            if c["state"] == "SYN_SENT":
                since = self._syn_since.setdefault(key, now)
                stuck = (now - since) >= SYN_STUCK_SECS
                if (stuck and self._net_initialised
                        and key not in self._syn_alerted):
                    self._syn_alerted.add(key)
                    self._alert(
                        f"OUTBOUND NOT ANSWERING: {c['process']} -> "
                        f"{c['ip']} still SYN_SENT after {int(now - since)}s "
                        f"(destination not replying - possibly blocked).",
                        "outbound")
            else:
                self._syn_since.pop(key, None)
                self._syn_alerted.discard(key)
            self._recent[key] = {
                "process": c["process"], "pid": c["pid"],
                "remote": c["remote"], "ip": c["ip"],
                "state": c["state"], "last": now, "open": True,
                "stuck": stuck,
            }
        for key, rec in self._recent.items():
            if key not in current:
                rec["open"] = False
                rec["stuck"] = False
        for key in [k for k, r in self._recent.items()
                    if now - r["last"] > self.RECENT_TTL]:
            del self._recent[key]
            self._syn_since.pop(key, None)
            self._syn_alerted.discard(key)
        view = sorted(self._recent.values(),
                      key=lambda r: (not r["open"], -r["last"]))
        self.emit("net", view)

        if not self._net_initialised:
            for c in conns:
                self.seen_net.add((c["process"], c["ip"]))
            self._net_initialised = True
            return
        for c in conns:
            key = (c["process"], c["ip"])
            if key in self.seen_net:
                continue
            self.seen_net.add(key)
            times = [t for t in self._net_burst.get(c["process"], [])
                     if now - t <= 30.0]
            times.append(now)
            self._net_burst[c["process"]] = times
            if key in self.trusted:
                continue
            self._alert(
                f"NEW OUTBOUND: {c['process']} (pid {c['pid']}) -> "
                f"{c['remote']} [{c['state']}]", "outbound")
            if len(times) >= 8:
                self._net_burst[c["process"]] = []
                self._alert(
                    f"OUTBOUND BURST: {c['process']} opened {len(times)}+ new "
                    f"connections within 30s (possible C2 / exfiltration).",
                    "outbound")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def check_baseline_age(self):
        ts = (self.baseline or {}).get("saved_at")
        if not ts:
            return
        days = (time.time() - ts) / 86400.0
        if days >= BASELINE_AGE_DAYS:
            self.emit("note",
                      f"Baseline is {int(days)} days old - click 'Take baseline "
                      f"snapshot' after any software installs.")

    def display_snapshot(self):
        return {
            "run": collect_run_entries(),
            "startup": collect_startup_files(),
            "tasks": collect_tasks(),
        }

    def _loop(self):
        self.check_defender()
        self.check_network()
        self.check_baseline_age()
        self.emit("startup", self.display_snapshot())
        self.check_persistence()
        self.check_tamper()
        while self._running:
            for _ in range(self.interval * 10):
                if not self._running:
                    return
                time.sleep(0.1)
            try:
                self.check_defender()
                self.check_network()
                self.check_persistence()
                self.check_tamper()
            except Exception as e:
                self.emit("status", f"check error: {e}")


# ----------------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------------
def _today_log_path():
    return os.path.join(DATA_DIR, f"pcguard-{time.strftime('%Y-%m-%d')}.log")


def append_log(line):
    path = _today_log_path()
    try:
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            n = 1
            while os.path.exists(path.replace(".log", f".{n}.log")):
                n += 1
            os.replace(path, path.replace(".log", f".{n}.log"))
    except Exception:
        pass
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_recent_log(max_lines=800):
    try:
        files = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR)
                 if f.startswith("pcguard-") and f.endswith(".log")]
        files.sort(key=os.path.getmtime, reverse=True)
    except Exception:
        files = []
    if not files:
        return []
    try:
        with open(files[0], "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return lines[-max_lines:]
    except Exception:
        return []


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json(path, obj):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
    except Exception:
        pass


# ============================================================================
# Themes (light / dark)
# ============================================================================
FONT_FAMILY = "Segoe UI"

THEMES = {
    "light": {
        "name": "Light",
        "bg": "#f4f6f5",
        "card": "#ffffff",
        "text": "#1c2330",
        "muted": "#5b6472",
        "border": "#dde3de",
        "accent": "#0a7adc",
        "accent_dark": "#075ea8",
        "warn": "#b42318",
        "ok": "#0a7adc",
        "stuck": "#b45309",
        "accent_fg": "white",
        "accent_disabled_bg": "#c2d3e4",
        "accent_disabled_fg": "#44566a",
        "neutral_disabled_bg": "#e2e5e7",
        "neutral_disabled_fg": "#8a949e",
        "field_bg": "#ffffff",
        "field_fg": "#1c2330",
        "neutral_hover": "#e8ece9",
        "tab_bg": "#f4f6f5",
        "tab_active": "#ffffff",
    },
    "dark": {
        "name": "Dark",
        "bg": "#14171c",
        "card": "#1e242c",
        "text": "#e3e7eb",
        "muted": "#9aa5b1",
        "border": "#343d48",
        "accent": "#3ea6ff",
        "accent_dark": "#2b87d8",
        "warn": "#ff6b6b",
        "ok": "#3ea6ff",
        "stuck": "#f0a44a",
        "accent_fg": "#04131f",
        "accent_disabled_bg": "#283c50",
        "accent_disabled_fg": "#9db3c9",
        "neutral_disabled_bg": "#2a313b",
        "neutral_disabled_fg": "#7a8590",
        "field_bg": "#161b22",
        "field_fg": "#e3e7eb",
        "neutral_hover": "#2a313b",
        "tab_bg": "#14171c",
        "tab_active": "#1e242c",
    },
}

# Log-tag colours mapped to theme keys.
LOG_TAGS = {
    "info": "text",
    "good": "ok",
    "warn": "stuck",
    "error": "warn",
    "header": "text",
    "dim": "muted",
}


class DefenderPCGuardApp(tk.Tk):
    def __init__(self):
        enable_hidpi()
        super().__init__()
        self.theme = dict(THEMES["light"])
        self.dark = False
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.configure(bg=self.theme["bg"])
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass

        try:
            self.scale = max(0.8, min(self.winfo_fpixels("1i") / 96.0, 3.0))
        except Exception:
            self.scale = 1.0

        def pt(n, bold=False):
            return (FONT_FAMILY, max(8, int(n)),
                    "bold" if bold else "normal")

        self.F_TITLE = pt(20, True)
        self.F_SECTION = pt(13, True)
        self.F_LABEL = pt(11)
        self.F_SUB = pt(10)
        self.F_MED = pt(11, True)
        self.F_BAR = pt(11)
        self.F_LIST = pt(14)

        self.q = queue.Queue()
        self.guard = Guard(self._emit_from_thread)
        self._alerts = 0
        self.def_busy = False

        self._build_styles()
        self._build_ui()

        try:
            refresh_startup_minimized()
        except Exception:
            pass

        self.sound_on = True
        self.tray = None
        self._last_notify = 0.0
        if HAS_TRAY:
            tray = TrayIcon(resource_path("icon.ico"), APP_NAME,
                            post=lambda a: self.q.put(("tray", a)))
            self.tray = tray if tray.available else None

        self.bind("<Unmap>", self._on_unmap)
        self.protocol("WM_DELETE_WINDOW", self._on_close_request)

        self.after(200, self._drain)
        self.guard.start()
        self.status_lbl.config(
            text=f"Monitoring every {self.guard.interval}s")
        if self.tray is not None:
            self._log("Tray icon active - minimise or close the window to keep "
                      "it running in the notification area.")
        self._load_log_history()

    # ---------------- themes ------------------------------------------------
    def _toggle_theme(self):
        self.dark = not self.dark
        self.theme = dict(THEMES["dark" if self.dark else "light"])
        self._apply_theme()

    def _apply_theme(self):
        t = self.theme
        self.configure(bg=t["bg"])
        style = ttk.Style(self)
        style.configure("TFrame", background=t["bg"])
        style.configure("Card.TFrame", background=t["card"])
        style.configure("TLabel", background=t["bg"], foreground=t["text"],
                        font=self.F_LABEL)
        style.configure("Card.TLabel", background=t["card"], foreground=t["text"],
                        font=self.F_LABEL)
        style.configure("Title.TLabel", background=t["bg"], foreground=t["text"],
                        font=self.F_TITLE)
        style.configure("Subtle.TLabel", background=t["bg"],
                        foreground=t["muted"], font=self.F_SUB)
        style.configure("Accent.TButton", background=t["accent"],
                        foreground=t["accent_fg"], font=self.F_MED,
                        borderwidth=0, padding=(14, 8))
        style.map("Accent.TButton",
                  background=[("active", t["accent_dark"]),
                              ("disabled", t["accent_disabled_bg"])],
                  foreground=[("disabled", t["accent_disabled_fg"])])
        style.configure("Neutral.TButton", background=t["card"],
                        foreground=t["text"], font=self.F_SUB, padding=(12, 6))
        style.map("Neutral.TButton",
                  background=[("active", t["neutral_hover"]),
                              ("disabled", t["neutral_disabled_bg"])],
                  foreground=[("disabled", t["neutral_disabled_fg"])])

        import tkinter.font as tkfont
        try:
            text_px = tkfont.Font(font=self.F_BAR).metrics("linespace")
        except Exception:
            text_px = 20
        indicator = max(16, int(round(text_px * 0.95)))
        ind_margin = max(8, int(round(text_px * 0.45)))
        style.configure("Bar.TCheckbutton", background=t["bg"],
                        foreground=t["text"], font=self.F_BAR, borderwidth=1)
        for opt, val in (("indicatordiameter", indicator),
                         ("indicatorsize", indicator),
                         ("indicatormargin", ind_margin)):
            try:
                style.configure("Bar.TCheckbutton", **{opt: val})
            except Exception:
                pass
        style.map("Bar.TCheckbutton",
                  background=[("active", t["bg"]), ("pressed", t["bg"]),
                              ("selected", t["bg"])],
                  foreground=[("active", t["text"]), ("pressed", t["text"]),
                              ("selected", t["text"])])

        # Defender-updater themed radios / checks (inside a card).
        # Indicators are slightly larger than the toolbar checkbox so the
        # radio circles / tick boxes read well next to 11pt labels.
        import tkinter.font as _tkfont
        try:
            label_px = _tkfont.Font(font=self.F_LABEL).metrics("linespace")
        except Exception:
            label_px = 20
        # Only a slight increase over the default indicator size.
        def_ind = max(16, int(round(label_px * 1.05)))
        def_margin = max(6, int(round(label_px * 0.35)))
        style.configure("Def.TRadiobutton", background=t["card"],
                        foreground=t["text"], font=self.F_LABEL)
        style.map("Def.TRadiobutton",
                  background=[("active", t["card"])],
                  foreground=[("active", t["text"])])
        style.configure("Def.TCheckbutton", background=t["card"],
                        foreground=t["text"], font=self.F_LABEL)
        style.map("Def.TCheckbutton",
                  background=[("active", t["card"])],
                  foreground=[("active", t["text"])])
        for _opt, _val in (("indicatordiameter", def_ind),
                           ("indicatorsize", def_ind),
                           ("indicatormargin", def_margin)):
            try:
                style.configure("Def.TCheckbutton", **{_opt: _val})
            except Exception:
                pass
            try:
                style.configure("Def.TRadiobutton", **{_opt: _val})
            except Exception:
                pass

        style.configure("TNotebook", background=t["tab_bg"], borderwidth=0)
        style.configure("TNotebook.Tab", font=self.F_MED, padding=(16, 8),
                        background=t["card"], foreground=t["text"])
        style.map("TNotebook.Tab",
                  background=[("selected", t["tab_active"])],
                  foreground=[("selected", t["text"])])
        style.configure("Treeview", font=self.F_LABEL,
                        rowheight=int(22 * self.scale),
                        background=t["field_bg"], fieldbackground=t["field_bg"],
                        foreground=t["text"])
        style.configure("Treeview.Heading", font=self.F_MED,
                        background=t["card"], foreground=t["text"])

        # Raw tk widgets - guarded so the first (pre-build) call is safe.
        for name in ("def_txt", "tamper_txt", "log_txt"):
            w = getattr(self, name, None)
            if w is not None:
                w.configure(bg=t["field_bg"], fg=t["field_fg"],
                            highlightbackground=t["border"])
        if getattr(self, "def_log_txt", None) is not None:
            self._configure_def_log_tags()
            self.def_log_txt.configure(bg=t["field_bg"], fg=t["field_fg"],
                                       highlightbackground=t["border"])

        if getattr(self, "net_tree", None) is not None:
            self.net_tree.tag_configure("new", foreground=t["warn"])
            self.net_tree.tag_configure("trusted", foreground=t["ok"])
            self.net_tree.tag_configure("closed", foreground=t["muted"])
            self.net_tree.tag_configure("stuck", foreground=t["stuck"])

        if getattr(self, "status_lbl", None) is not None:
            self.status_lbl.configure(background=t["card"],
                                      foreground=t["accent_dark"])
        if getattr(self, "alert_lbl", None) is not None:
            self.alert_lbl.configure(background=t["card"],
                                     foreground=t["muted"])
        if getattr(self, "theme_btn", None) is not None:
            self.theme_btn.config(text="Theme: Dark" if not self.dark
                                  else "Theme: Light")
        if getattr(self, "log_txt", None) is not None:
            self._log(f"Theme switched to {self.theme['name']}.")

    def _configure_def_log_tags(self):
        t = self.theme
        for k, key in LOG_TAGS.items():
            self.def_log_txt.tag_configure(k, foreground=t[key])
        self.def_log_txt.tag_configure("bold",
                                       font=("Consolas", 10, "bold"))

    # ---------------- styles (initial build) --------------------------------
    def _build_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # Set the light palette first (calls _apply_theme after widgets exist).
        self._apply_theme()

    # ---------------- layout ------------------------------------------------
    def _build_ui(self):
        root = ttk.Frame(self, padding=(18, 14))
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)
        self.root_frame = root

        header = ttk.Frame(root)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Label(header,
                  text=("Update Microsoft Defender and watch persistence, "
                        "tamper and outbound activity."),
                  style="Subtle.TLabel").grid(row=1, column=0, sticky="w")

        bar = ttk.Frame(root)
        bar.grid(row=1, column=0, sticky="ew", pady=(10, 6))
        ttk.Button(bar, text="Take baseline snapshot", style="Accent.TButton",
                   command=self._take_baseline).pack(side="left")
        ttk.Button(bar, text="Scan now", style="Neutral.TButton",
                   command=self._scan_now).pack(side="left", padx=6)
        self.mon_btn = ttk.Button(bar, text="Stop monitoring",
                                  style="Neutral.TButton",
                                  command=self._toggle_monitor)
        self.mon_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Trust selected", style="Neutral.TButton",
                   command=self._trust_selected).pack(side="left", padx=6)
        ttk.Button(bar, text="Manage trusted...", style="Neutral.TButton",
                   command=self._manage_trusted).pack(side="left", padx=6)
        self.startup_var = tk.BooleanVar(value=startup_enabled())
        self.startup_chk = ttk.Checkbutton(
            bar, text="Start with Windows", variable=self.startup_var,
            command=self._toggle_startup, style="Bar.TCheckbutton")
        self.startup_chk.pack(side="left", padx=(10, 0))
        self.sound_btn = ttk.Button(bar, text="Sound: ON",
                                    style="Neutral.TButton",
                                    command=self._toggle_sound)
        self.sound_btn.pack(side="right")
        ttk.Button(bar, text="Export log...", style="Neutral.TButton",
                   command=self._export_log).pack(side="right", padx=(0, 8))
        ttk.Button(bar, text="Clear alerts", style="Neutral.TButton",
                   command=self._clear_alerts).pack(side="right", padx=(0, 8))

        self.nb = ttk.Notebook(root)
        self.nb.grid(row=2, column=0, sticky="nsew")
        # New tab goes FIRST (left of the Dashboard).
        self._build_defender_tab(self.nb)
        self._build_dashboard(self.nb)
        self._build_network(self.nb)
        self._build_startup(self.nb)
        self._build_tamper(self.nb)
        self._build_log(self.nb)

        statusbar = ttk.Frame(root, style="Card.TFrame", padding=(10, 6))
        statusbar.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        statusbar.columnconfigure(0, weight=1)
        self.status_lbl = ttk.Label(statusbar, text="Starting...",
                                    style="Card.TLabel", anchor="w")
        self.status_lbl.grid(row=0, column=0, sticky="ew")
        self.alert_lbl = ttk.Label(statusbar, text="Alerts: 0",
                                   style="Card.TLabel")
        self.alert_lbl.grid(row=0, column=1, sticky="e", padx=(12, 0))

        footer = ttk.Frame(root)
        footer.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(footer, text=f"Version {APP_VERSION}",
                  style="Subtle.TLabel").pack(side="left")
        ttk.Button(footer, text="Exit", style="Neutral.TButton",
                   command=self._on_close).pack(side="right", padx=(6, 0))
        ttk.Button(footer, text="About", style="Neutral.TButton",
                   command=self._show_about).pack(side="right", padx=(6, 0))
        # Theme toggle sits right next to About, with the same spacing.
        self.theme_btn = ttk.Button(footer, text="Theme: Dark",
                                    style="Neutral.TButton",
                                    command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=(6, 0))

    # ------ Defender Update tab (left of Dashboard) -------------------------
    def _build_defender_tab(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=12)
        nb.add(f, text="Defender Update")
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

        # Split the tab into two side-by-side panes: controls on the left,
        # the live details log filling the (previously empty) right side.
        paned = ttk.Panedwindow(f, orient="horizontal")
        paned.grid(row=0, column=0, sticky="nsew")

        # --- Left pane: options / buttons / status -------------------------
        left = ttk.Frame(paned, style="Card.TFrame", padding=(2, 0, 16, 0))
        paned.add(left, weight=1)

        ttk.Label(left, text="Update Windows Defender",
                  style="Card.TLabel", font=self.F_SECTION).pack(anchor="w")
        ttk.Label(
            left,
            text=("Check and update your virus definitions, and compare what "
                  "you have against the latest Microsoft has published. "
                  "No technical knowledge needed."),
            style="Card.TLabel", justify="left", wraplength=400).pack(
                anchor="w", pady=(2, 10))

        group = ttk.Frame(left, style="Card.TFrame")
        group.pack(fill="x", anchor="w", pady=(0, 10))
        ttk.Label(group,
                  text="How should Defender download its virus definitions?",
                  style="Card.TLabel", font=self.F_MED).pack(
                      anchor="w", pady=(0, 3))

        self.method = tk.StringVar(value="auto")
        options = [
            ("Automatic (recommended) - online, with offline fallback", "auto"),
            ("Online only (needs internet)", "online"),
            ("Offline only (downloads from Microsoft)", "offline"),
        ]
        for text, val in options:
            ttk.Radiobutton(group, text=text, variable=self.method,
                            value=val, style="Def.TRadiobutton").pack(
                                anchor="w", padx=4, pady=1)
        self.engine_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            group,
            text="Also check for the scanning ENGINE update (needs admin)",
            variable=self.engine_var, style="Def.TCheckbutton").pack(
                anchor="w", padx=4, pady=(5, 0))

        btns = ttk.Frame(left, style="Card.TFrame")
        btns.pack(anchor="w", fill="x", pady=(0, 10))
        self.def_update_btn = ttk.Button(btns, text="Update Defender",
                                         style="Accent.TButton",
                                         command=self.on_update)
        self.def_update_btn.pack(side="left")
        self.def_check_btn = ttk.Button(btns, text="Check Current Version",
                                        style="Accent.TButton",
                                        command=self.on_check)
        self.def_check_btn.pack(side="left", padx=(8, 0))
        self.def_clear_btn = ttk.Button(btns, text="Clear Log",
                                        style="Neutral.TButton",
                                        command=self.def_clear_log)
        self.def_clear_btn.pack(side="left", padx=(8, 0))

        status_row = ttk.Frame(left, style="Card.TFrame")
        status_row.pack(fill="x", anchor="w")
        self.def_status_var = tk.StringVar(value="Ready.")
        self.def_status_lbl = ttk.Label(status_row,
                                        textvariable=self.def_status_var,
                                        style="Card.TLabel", anchor="w")
        self.def_status_lbl.pack(fill="x")

        # --- Right pane: details log (uses the empty space below) ----------
        right = ttk.Frame(paned, style="Card.TFrame", padding=(4, 0, 0, 0))
        paned.add(right, weight=3)
        ttk.Label(right, text="Details log",
                  style="Card.TLabel", font=self.F_MED).pack(anchor="w",
                                                             pady=(0, 4))
        wrap = ttk.Frame(right, style="Card.TFrame")
        wrap.pack(fill="both", expand=True)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self.def_log_txt = tk.Text(wrap, font=("Consolas", 10),
                                   wrap="word", relief="flat", bd=0,
                                   padx=10, pady=10, state="disabled")
        scroll = ttk.Scrollbar(wrap, orient="vertical",
                               command=self.def_log_txt.yview)
        self.def_log_txt.configure(yscrollcommand=scroll.set)
        self.def_log_txt.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self._configure_def_log_tags()

    def _build_dashboard(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=16)
        nb.add(f, text="Dashboard")
        ttk.Label(f, text="Defender status", style="Card.TLabel",
                  font=self.F_SECTION).grid(row=0, column=0, sticky="w")
        self.def_txt = tk.Text(f, height=9, width=60, wrap="word",
                               font=self.F_LABEL, bg=self.theme["field_bg"],
                               fg=self.theme["field_fg"], relief="flat",
                               padx=6, pady=6, highlightthickness=1)
        self.def_txt.grid(row=1, column=0, sticky="nsew", pady=(6, 10))
        ttk.Label(f, text="How PC Guard helps", style="Card.TLabel",
                  font=self.F_SECTION).grid(row=2, column=0, sticky="w")
        ttk.Label(
            f,
            text=("• Persistence: flags anything new that auto-starts.\n"
                  "• Tamper: flags hosts-file / DNS changes and new Defender "
                  "exclusions or disabled real-time protection.\n"
                  "• Outbound: flags new process -> remote pairs. 'Trust "
                  "selected' silences ones you recognise.\n"
                  "This is a watchdog (alerts), not a blocker. Keep Defender on."),
            style="Card.TLabel", justify="left").grid(row=3, column=0,
                                                      sticky="w")
        f.columnconfigure(0, weight=1)

    def _build_network(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=10)
        nb.add(f, text="Network (outbound)")
        ttk.Label(
            f,
            text=("Live connections, plus any seen in the last 5 minutes. "
                  "Status: 'Open' = connected now; 'Connecting' = handshake "
                  "in progress; 'Blocked?' = not answering for 10s+ (down or "
                  "firewalled); 'Closed' = seen recently, has since ended. "
                  "Colours: red = new this session, amber = not answering, "
                  "grey = closed, green = trusted."),
            style="Card.TLabel", justify="left", wraplength=2000).pack(
                fill="x", pady=(0, 6))
        cols = ("process", "pid", "remote", "state", "seen")
        self.net_tree = ttk.Treeview(f, columns=cols, show="headings",
                                     height=16)
        for c, w, t in (("process", 200, "Process"), ("pid", 80, "PID"),
                        ("remote", 300, "Remote"), ("state", 110, "Status"),
                        ("seen", 120, "Last seen")):
            self.net_tree.heading(c, text=t)
            self.net_tree.column(c, width=w, anchor="w")
        self.net_tree.tag_configure("new", foreground=self.theme["warn"])
        self.net_tree.tag_configure("trusted", foreground=self.theme["ok"])
        self.net_tree.tag_configure("closed", foreground=self.theme["muted"])
        self.net_tree.tag_configure("stuck", foreground=self.theme["stuck"])
        self.net_tree.pack(fill="both", expand=True)

    def _build_startup(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=10)
        nb.add(f, text="Startup / persistence")
        ttk.Label(
            f,
            text="Everything that starts automatically on this PC (registry Run keys, Startup folder, Scheduled Tasks).",
            style="Card.TLabel", justify="left", wraplength=1600).pack(
                fill="x", pady=(0, 2))
        ttk.Label(
            f,
            text="PC Guard watches this list for changes - any new/changed/removed item is reported in the Alerts tab. Click 'Scan now' to refresh.",
            style="Card.TLabel", justify="left", wraplength=1700).pack(
                fill="x", pady=(0, 6))
        cols = ("type", "name", "value")
        wrap = ttk.Frame(f, style="Card.TFrame")
        wrap.pack(fill="both", expand=True)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self.start_tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                       height=16)
        for c, w, t in (("type", 170, "Type"), ("name", 380, "Name"),
                        ("value", 900, "Command / path")):
            self.start_tree.heading(c, text=t)
            self.start_tree.column(c, width=w, minwidth=w, stretch=False,
                                   anchor="w")
        vsb = ttk.Scrollbar(wrap, orient="vertical",
                            command=self.start_tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal",
                            command=self.start_tree.xview)
        self.start_tree.configure(yscrollcommand=vsb.set,
                                  xscrollcommand=hsb.set)
        self.start_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

    def _build_tamper(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=16)
        nb.add(f, text="Alerts")
        self.tamper_txt = tk.Text(f, wrap="word", font=self.F_LABEL,
                                  bg=self.theme["field_bg"],
                                  fg=self.theme["field_fg"], relief="flat",
                                  padx=6, pady=6, highlightthickness=1)
        self.tamper_txt.pack(fill="both", expand=True)
        self.tamper_txt.bind("<Button-3>", self._alerts_menu)

    def _build_log(self, nb):
        f = ttk.Frame(nb, style="Card.TFrame", padding=10)
        nb.add(f, text="Log")
        self.log_txt = tk.Text(f, wrap="word", font=self.F_LABEL,
                               bg=self.theme["field_bg"],
                               fg=self.theme["field_fg"], relief="flat",
                               padx=6, pady=6, highlightthickness=1)
        self.log_txt.pack(fill="both", expand=True)

    # ---------------- helper accessors -------------------------------------
    def _theme_text(self):
        return self.theme

    # ---------------- actions: guard ---------------------------------------
    def _take_baseline(self):
        threading.Thread(target=self.guard.take_snapshot, daemon=True).start()

    def _scan_now(self):
        self.q.put(("status", "Scanning..."))

        def work():
            st = collect_defender_status()
            if st:
                self.q.put(("defender", st))
            snap = self.guard.display_snapshot()
            self.q.put(("startup", snap))
            conns = collect_connections()
            self.q.put(("net", conns))
            before = self.guard.alert_count
            self.guard.check_persistence()
            self.guard.check_tamper()
            n_auto = (len(snap["run"]) + len(snap["startup"])
                      + len(snap["tasks"]))
            found = self.guard.alert_count - before
            msg = (f"Scan complete: {n_auto} auto-start item(s), "
                   f"{len(conns)} connection(s) checked. ")
            msg += (f"{found} change(s) found - see the Alerts tab."
                    if found else "No changes vs your baseline.")
            self.q.put(("scan_done", msg))
        threading.Thread(target=work, daemon=True).start()

    def _toggle_monitor(self):
        if self.guard._running:
            self.guard.stop()
            self.mon_btn.config(text="Start monitoring")
            self.q.put(("status", "Monitoring stopped."))
        else:
            self.guard.start()
            self.mon_btn.config(text="Stop monitoring")
            self.q.put(("status", "Monitoring started."))

    def _trust_selected(self):
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME,
                                "Select one or more rows in the Network tab.")
            return
        for iid in sel:
            vals = self.net_tree.item(iid, "values")
            proc, ip = vals[0], vals[2].rsplit(":", 1)[0]
            self.guard.trusted.add((proc, ip))
            self.net_tree.item(iid, tags=("trusted",))
        self.guard.save_trusted()
        self.q.put(("status", "Trusted selection saved. See 'Manage trusted...'."))

    def _manage_trusted(self):
        dlg = self._make_modal("Trusted connections", 1120, 840)
        dlg.resizable(True, True)
        tk.Label(
            dlg,
            text=("Connections you've marked as trusted (PC Guard stays quiet "
                  "about them). Select one and Remove it to start alerting on "
                  "it again."),
            font=self.F_LABEL, justify="left", anchor="w", wraplength=1000,
            bg=self.theme["bg"], fg=self.theme["text"]).pack(
                fill="x", padx=14, pady=(12, 8))
        lb_wrap = ttk.Frame(dlg)
        lb_wrap.pack(fill="both", expand=True, padx=12)
        lb_wrap.rowconfigure(0, weight=1)
        lb_wrap.columnconfigure(0, weight=1)
        lb = tk.Listbox(lb_wrap, font=self.F_LIST,
                        bg=self.theme["field_bg"], fg=self.theme["field_fg"])
        vsb = ttk.Scrollbar(lb_wrap, orient="vertical", command=lb.yview)
        hsb = ttk.Scrollbar(lb_wrap, orient="horizontal", command=lb.xview)
        lb.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        lb.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        def refresh():
            lb.delete(0, "end")
            for proc, ip in sorted(self.guard.trusted):
                lb.insert("end", f"  {proc}  ->  {ip}")
            if not self.guard.trusted:
                lb.insert("end", "(nothing trusted yet)")
        refresh()

        btns = ttk.Frame(dlg)
        btns.pack(fill="x", padx=14, pady=(12, 14))

        def remove_sel():
            for i in reversed(lb.curselection()):
                parts = lb.get(i).split("->")
                if len(parts) == 2:
                    self.guard.trusted.discard(
                        (parts[0].strip(), parts[1].strip()))
            self.guard.save_trusted()
            refresh()
            self._render_network(getattr(self, "_net_view", []))

        def clear_all():
            if messagebox.askyesno(APP_NAME, "Remove ALL trusted entries?"):
                self.guard.trusted.clear()
                self.guard.save_trusted()
                refresh()
                self._render_network(getattr(self, "_net_view", []))

        ttk.Button(btns, text="Remove selected", style="Neutral.TButton",
                   command=remove_sel).pack(side="left", padx=(0, 8), ipady=6)
        ttk.Button(btns, text="Clear all", style="Neutral.TButton",
                   command=clear_all).pack(side="left", padx=(0, 8), ipady=6)
        ttk.Button(btns, text="Close", style="Neutral.TButton",
                   command=dlg.destroy).pack(side="right", padx=(8, 0), ipady=6)

    def _show_def_summary(self, title, lines, good):
        """Themed summary used by the Defender version check / update, so it
        matches the current light or dark theme (native messagebox does not).
        Sized generously and resizable so long lines never wrap to a sliver
        and the Close button is always visible."""
        dlg = self._make_modal(title, 760, 560)
        dlg.resizable(True, True)
        dlg.minsize(640, 520)
        t = self.theme

        head = ("OK: " if good else "!! ") + title  # ASCII to avoid encoding issues
        tk.Label(dlg, text=head, font=self.F_MED, bg=t["bg"],
                 fg=(t["ok"] if good else t["warn"]), anchor="w",
                 justify="left").pack(fill="x", padx=20, pady=(12, 8))

        body = tk.Text(dlg, wrap="word", font=self.F_LABEL,
                       width=104, height=10, bg=t["field_bg"],
                       fg=t["field_fg"], relief="flat", padx=12, pady=12)
        body.pack(fill="both", expand=True, padx=20, pady=(4, 8))
        for ln in lines:
            if str(ln).strip().startswith("All good"):
                body.insert("end", ln + "\n", "ok")
            elif any(w in str(ln).upper() for w in ("OUT OF DATE", "NOT",
                                                     "NEEDS", "SWITCHED OFF",
                                                     "DISABLED")):
                body.insert("end", ln + "\n", "warn")
            else:
                body.insert("end", ln + "\n")
        body.configure(state="disabled", highlightthickness=1,
                       highlightbackground=t["border"])
        body.tag_configure("ok", foreground=t["ok"], font=self.F_MED)
        body.tag_configure("warn", foreground=t["warn"], font=self.F_MED)

        # Reserve the bottom row for the button BEFORE packing the expanding
        # text area, so the button can never be squeezed to nothing.
        foot = tk.Frame(dlg, bg=t["bg"])
        foot.pack(side="bottom", fill="x", padx=20, pady=(0, 14))
        tk.Button(foot, text="Close", command=dlg.destroy, bg=t["accent"],
                  fg=t["accent_fg"], activebackground=t["accent_dark"],
                  activeforeground=t["accent_fg"], relief="flat", bd=0,
                  font=self.F_MED, padx=26, pady=9).pack()

    def _show_about(self):
        dlg = self._make_modal(f"About {APP_NAME}", 720, 460)
        t = self.theme
        tk.Label(dlg, text=about_text(), font=self.F_LABEL,
                 justify="center", bg=t["bg"], fg=t["text"]).pack(
                     expand=True, pady=30)
        tk.Button(dlg, text="Close", command=dlg.destroy,
                  font=self.F_MED, padx=20, pady=8, bg=t["accent"],
                  fg=t["accent_fg"], activebackground=t["accent_dark"],
                  activeforeground=t["accent_fg"],
                  relief="flat", bd=0).pack(pady=12)

    def _toggle_sound(self):
        self.sound_on = not self.sound_on
        self.sound_btn.config(text=f"Sound: {'ON' if self.sound_on else 'OFF'}")
        self._log(f"Alert sound {'enabled' if self.sound_on else 'muted'}.")

    def _clear_alerts(self):
        self._alerts = 0
        self.alert_lbl.config(text="Alerts: 0", foreground=self.theme["muted"])
        self.tamper_txt.delete("1.0", "end")
        self._log("Alerts cleared (view only - the log file is untouched).")

    def _load_log_history(self):
        lines = load_recent_log(800)
        if not lines:
            return
        for ln in lines:
            self.log_txt.insert("end", ln + "\n")
        self.log_txt.see("end")
        n_alerts = sum(1 for ln in lines if "ALERT:" in ln)
        if n_alerts:
            self.status_lbl.config(
                text=f"History loaded: {n_alerts} alert(s) in the most recent "
                     f"log ({len(lines)} lines).")
        else:
            self.status_lbl.config(
                text=f"History loaded: {len(lines)} previous log lines.")

    def _toggle_startup(self):
        want = self.startup_var.get()
        if not set_startup(want):
            self.startup_var.set(startup_enabled())
            messagebox.showwarning(
                APP_NAME, "Could not update the Windows startup setting.")
            return
        self._log(f"Start with Windows {'enabled' if want else 'disabled'}.")
        self.status_lbl.config(
            text=f"Start with Windows {'enabled' if want else 'disabled'}.")

    def _export_log(self):
        text = self.log_txt.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo(APP_NAME, "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export log", defaultextension=".txt",
            initialfile="pcguard_log.txt",
            filetypes=[("Text file", "*.txt"), ("CSV file", "*.csv"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write("timestamp,event\n")
                    for ln in text.splitlines():
                        if ln.startswith("[") and "] " in ln:
                            ts, ev = ln[1:].split("] ", 1)
                        else:
                            ts, ev = "", ln
                        ev = ev.replace('"', '""')
                        f.write(f'"{ts}","{ev}"\n')
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text + "\n")
            self._log(f"Log exported to {path}")
            self.status_lbl.config(text=f"Log exported to {path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed:\n{e}")

    # ---------------- actions: defender updater ----------------------------
    def def_clear_log(self):
        self.def_log_txt.configure(state="normal")
        self.def_log_txt.delete("1.0", "end")
        self.def_log_txt.configure(state="disabled")

    def _def_set_busy(self, busy):
        self.def_busy = busy
        state = "disabled" if busy else "normal"
        self.def_update_btn.configure(state=state)
        self.def_check_btn.configure(state=state)

    def _def_log(self, text, tag="info", bold=False):
        self.def_log_txt.configure(state="normal")
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n"
        tags = (tag, "bold") if bold else (tag,)
        self.def_log_txt.insert("end", line, tags)
        self.def_log_txt.see("end")
        self.def_log_txt.configure(state="disabled")

    def on_check(self):
        if self.def_busy:
            return
        self._def_set_busy(True)
        self.def_clear_log()
        self.def_status_var.set("Checking...")
        threading.Thread(target=self._check_worker, daemon=True).start()

    def on_update(self):
        if self.def_busy:
            return
        self._def_set_busy(True)
        self.def_clear_log()
        self.def_status_var.set("Starting...")
        args = (self.method.get(), self.engine_var.get())
        threading.Thread(target=self._update_worker, args=args,
                         daemon=True).start()

    def _post_def_log(self, text, tag="info", bold=False):
        self.q.put(("def_log", (text, tag, bold)))

    def _post_def_status(self, text):
        self.q.put(("def_status", text))

    # ---------------- check worker -----------------------------------------
    def _check_worker(self):
        try:
            self._post_def_log("Reading current Defender status...", "dim")
            s = get_local_status()
            rt = s["rt"]
            self._post_def_log("")
            self._post_def_log("==================  CURRENT DEFENDER STATUS  ==================", "header", True)
            good_tag = "good" if rt else "warn"
            self._post_def_log(f"Real-time protection      : {'ON (protecting this PC)' if rt else 'OFF - needs attention'}", good_tag)
            self._post_def_log(f"Virus definition version : {s['sig_version']}")
            self._post_def_log(f"Definitions last updated : {s['sig_date']}")
            self._post_def_log(f"Scanning engine version  : {s['engine']}")
            self._post_def_log(f"Product version          : {s['product']}")

            self._post_def_status("Contacting Microsoft for the latest version...")
            self._post_def_log("Contacting Microsoft to check the latest published versions...", "dim")
            latest = get_latest_online()
            self._post_def_log("LATEST FROM MICROSOFT (online):", "header", True)
            self._post_def_log(f"  Definitions version : {latest['version']}")
            self._post_def_log(f"  Engine version      : {latest['engine']}")
            self._post_def_log(f"  Platform version    : {latest['platform']}")
            self._post_def_log(f"  Released            : {latest['released']}")
            self._post_def_log("")

            def_cmp = compare_versions(s["sig_version"], latest["version"])
            eng_cmp = compare_versions(s["engine"], latest["engine"])

            if def_cmp >= 0:
                self._post_def_log(f"Virus definitions: UP TO DATE with Microsoft (version {s['sig_version']}).", "good")
            else:
                self._post_def_log(f"Virus definitions: OUT OF DATE - you have {s['sig_version']}, Microsoft has {latest['version']}.", "warn")
                self._post_def_log("  Press 'Update Defender' to fix this.", "warn")
            if eng_cmp >= 0:
                self._post_def_log(f"Scanning engine  : UP TO DATE with Microsoft (engine {s['engine']}).", "good")
            else:
                self._post_def_log(f"Scanning engine  : OUT OF DATE - you have {s['engine']}, Microsoft has {latest['engine']}.", "warn")

            lines = []
            good = True
            lines.append("Real-time protection is ON - defending this PC." if rt
                         else "REAL-TIME PROTECTION IS OFF - Defender is NOT protecting this PC!")
            if not rt:
                good = False
            if def_cmp >= 0:
                lines.append(f"Virus definitions up to date ({s['sig_version']}).")
            else:
                lines.append(f"Virus definitions OUT OF DATE: you have {s['sig_version']}, Microsoft has {latest['version']}.")
                good = False
            if eng_cmp >= 0:
                lines.append(f"Scanning engine up to date ({s['engine']}).")
            else:
                lines.append(f"Scanning engine OUT OF DATE ({s['engine']}).")
                good = False
            lines.append("")
            lines.append("All good - protection is current." if good else "Run 'Update Defender' to bring protection up to date.")
            self.q.put(("def_summary", ("Version Check", lines, good)))
        except Exception as e:
            self._post_def_log(f"Check failed: {e}", "error")
            self._post_def_log("You can still use 'Update Defender' to pull the latest definitions.", "dim")
        self.q.put(("def_status", "Check complete."))
        self.q.put(("def_done", None))

    # ---------------- update worker ----------------------------------------
    def _update_worker(self, method, do_engine):
        try:
            self._post_def_log("Reading current Defender status...", "dim")
            before = get_local_status()
            self._post_def_log("")
            self._post_def_log("----- Before update -----", "header", True)
            self._print_def_status(before)

            self._post_def_log("")
            if method == "online":
                self._run_online_defs()
            elif method == "offline":
                self._run_offline_defs()
            else:
                ok = self._run_online_defs(stream=True)
                if not ok:
                    self._post_def_log("Online update failed - falling back to the offline package...", "warn")
                    self._run_offline_defs()

            if do_engine:
                self._post_def_log("")
                if not def_is_admin():
                    self._post_def_log("Engine update needs Administrator rights.", "warn")
                    self._post_def_log("Right-click the launcher and choose 'Run as administrator'.", "warn")
                else:
                    self._run_engine_update()

            self._post_def_log("")
            self._post_def_log("----- After update -----", "header", True)
            after = get_local_status()
            self._print_def_status(after)

            lines = []
            good = True
            if after["rt"]:
                lines.append("Real-time protection is ON - protecting this PC.")
            else:
                lines.append("REAL-TIME PROTECTION IS OFF - Defender is NOT protecting this PC!")
                good = False
            if before["sig_version"] != after["sig_version"]:
                lines.append(f"Virus definitions UPDATED: {before['sig_version']}  ->  {after['sig_version']}")
            else:
                lines.append(f"Virus definitions already up to date (version {after['sig_version']}).")
            if do_engine and before["engine"] != after["engine"]:
                lines.append(f"Scanning engine UPDATED: {before['engine']}  ->  {after['engine']}")
            elif do_engine:
                lines.append(f"Scanning engine is the latest ({after['engine']}).")
            lines.append("")
            lines.append("All good - Defender is up to date and protecting this PC." if good
                         else "Protection needs attention - see the log for details.")
            self.q.put(("def_summary", ("Defender Update", lines, good)))
        except Exception as e:
            self._post_def_log(f"Update failed: {e}", "error")
        self.q.put(("def_status", "Update finished - see summary."))
        self.q.put(("def_done", None))

    def _print_def_status(self, s):
        tag = "good" if s["rt"] else "warn"
        self._post_def_log(f"Real-time protection        : {'ON (Protecting this PC)' if s['rt'] else 'OFF - NOT protecting'}", tag)
        self._post_def_log(f"Definition version          : {s['sig_version']}")
        self._post_def_log(f"Definitions last updated    : {s['sig_date']}")
        self._post_def_log(f"Scanning engine version     : {s['engine']}")
        self._post_def_log(f"Product version             : {s['product']}")

    def _run_online_defs(self, stream=False):
        self._post_def_status("Updating your virus definitions...")
        self._post_def_log("Updating virus definitions (online)...")
        ok = True
        rc, out, err = run_ps_full("Update-MpSignature", timeout=180)
        for line in out.splitlines():
            stripped = line.strip()
            if stripped:
                tag = "good" if "success" in stripped.lower() else "info"
                self._post_def_log(f"  {stripped}", tag)
        if rc != 0 and not out.strip():
            ok = False
            self._post_def_log(f"Online update failed: {err.strip() or 'unknown error'}", "error")
        return ok

    def _run_offline_defs(self):
        self._post_def_status("Downloading offline definitions from Microsoft...")
        self._post_def_log("Downloading the offline definition package from Microsoft...")
        self._post_def_log("  (this can take a little while)", "dim")
        url = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"
        dest = os.path.join(
            os.environ.get("TEMP", os.path.expanduser("~")), "mpam-fe.exe")
        try:
            # Streamed download with a timeout - urlretrieve() has none and
            # could hang the update worker forever on a stalled connection.
            req = urllib.request.Request(
                url, headers={
                    "User-Agent":
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=120) as r, \
                    open(dest, "wb") as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
            self._post_def_log("  Downloaded. Installing...")
            script = (f"$p = Start-Process -FilePath '{dest}' "
                      f"-ArgumentList '/q' -Wait -PassThru; $p.ExitCode")
            rc, out, err = run_ps_full(script, timeout=360)
            code = out.strip()
            if code == "0":
                self._post_def_log("Offline package installed OK.", "good")
            else:
                self._post_def_log(
                    f"Offline installer exit code: {code or 'unknown'} "
                    f"({err.strip()})", "warn")
        finally:
            try:
                os.remove(dest)
            except Exception:
                pass

    def _run_engine_update(self):
        self._post_def_status("Checking for a newer scanning engine...")
        self._post_def_log("Checking for a newer scanning engine via Windows Update...")
        script = (
            "$s = New-Object -ComObject Microsoft.Update.Session;"
            "$se = $s.CreateUpdateSearcher();"
            "$r = $se.Search(\"IsInstalled=0 and Type='Software'\").Updates;"
            "$c = @();"
            "foreach ($u in $r) { if ($u.Title -match 'Defender|Antimalware|Security Intelligence|Engine') { $c += $u } };"
            "if ($c.Count -eq 0) { 'NO_ENGINE_UPDATES' } else {"
            "  foreach ($u in $c) {"
            "    $d = $s.CreateUpdateDownloader(); $d.Updates = $u; $x = $d.Download();"
            "    if ($x.ResultCode -eq 2) {"
            "      $i = $s.CreateUpdateInstaller(); $i.Updates = $u; $y = $i.Install();"
            "      'Installed: ' + $u.Title + ' (result ' + $y.ResultCode + ')'"
            "    } else { 'Download issue: ' + $u.Title }"
            "  }"
            "}"
        )
        rc, out, err = run_ps_full(script, timeout=300)
        out = out.strip()
        if "NO_ENGINE_UPDATES" in out:
            self._post_def_log("No engine updates pending - your engine is already the latest.", "good")
        elif out:
            for line in out.splitlines():
                tag = "good" if "Installed" in line else "warn"
                self._post_def_log(f"  {line.strip()}", tag)
        else:
            self._post_def_log(f"Engine update step gave no result ({err.strip() or 'no output'}).", "warn")

    # ---------------- ignore list ------------------------------------------
    def _alerts_menu(self, event):
        self._rclick = (event.x, event.y)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Ignore this alert",
                         command=self._ignore_alert_here)
        menu.add_command(label="Clear ignored alerts",
                         command=self._clear_ignored)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _ignore_alert_here(self):
        x, y = getattr(self, "_rclick", (0, 0))
        try:
            idx = self.tamper_txt.index(f"@{x},{y}")
            line = self.tamper_txt.get(idx + " linestart",
                                       idx + " lineend").strip()
        except Exception:
            return
        line = line.lstrip("• ").strip()
        if not line:
            return
        self.guard.ignored.add(line)
        self.guard.save_ignored()
        self._log(f"Ignoring alerts like: {line}")
        self.status_lbl.config(text="Alert added to the ignore list.")

    def _clear_ignored(self):
        n = len(self.guard.ignored)
        self.guard.ignored.clear()
        self.guard.save_ignored()
        self._log(f"Cleared {n} ignored alert(s).")
        self.status_lbl.config(text=f"Cleared {n} ignored alert(s).")

    # ---------------- tray / window ----------------------------------------
    def _on_unmap(self, event):
        if event.widget is not self or self.tray is None:
            return
        if self.state() == "iconic":
            self.hide_to_tray()

    def hide_to_tray(self, quiet=False):
        self.withdraw()
        if not quiet:
            self._log("Minimised to the notification area.")
            self.status_lbl.config(text="Running in the notification area.")

    def show_window(self):
        try:
            self.attributes("-alpha", 1.0)
        except Exception:
            pass
        self.deiconify()
        self.lift()
        # Restore full-screen / maximised state when bringing the window back.
        # (Fixes the tray case: starting minimised at login used to reappear
        # un-maximised and shifted off to the right.)
        self._restore_maximized()
        try:
            self.focus_force()
        except Exception:
            pass

    def _restore_maximized(self, retries=6):
        """Keep trying to set the maximised state so it persists once the
        window is actually mapped (Tk may ignore it while still mapping)."""
        try:
            self.state("zoomed")
        except Exception:
            pass
        if retries > 0:
            self.after(80, lambda: self._restore_maximized(retries - 1))

    def _on_close_request(self):
        if self.tray is None:
            self._on_close()
            return
        self.hide_to_tray(quiet=True)
        try:
            self.tray.notify(APP_NAME + " is still running in the notification "
                             "area. Right-click the tray icon to Exit.")
        except Exception:
            pass

    def _on_close(self):
        try:
            self.guard.stop()
        except Exception:
            pass
        if getattr(self, "tray", None) is not None:
            self.tray.stop()
            self.tray = None
        self.destroy()

    def _make_modal(self, title, w, h):
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()
        dlg.configure(bg=self.theme["bg"])
        try:
            dlg.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass
        dlg.geometry(f"{w}x{h}")
        dlg.update_idletasks()
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            mh = user32.GetAncestor(self.winfo_id(), 2)
            dh = user32.GetAncestor(dlg.winfo_id(), 2)
            mr = wintypes.RECT(); dr = wintypes.RECT()
            user32.GetWindowRect(mh, ctypes.byref(mr))
            user32.GetWindowRect(dh, ctypes.byref(dr))
            dw = dr.right - dr.left
            dhh = dr.bottom - dr.top
            x = mr.left + ((mr.right - mr.left) - dw) // 2
            y = mr.top + ((mr.bottom - mr.top) - dhh) // 2
            user32.SetWindowPos(dh, 0, x, y, 0, 0, 0x0001 | 0x0004)
        except Exception:
            pass
        return dlg

    # ---------------- event pump -------------------------------------------
    def _emit_from_thread(self, kind, payload):
        self.q.put((kind, payload))

    def _drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                try:
                    self._handle(kind, payload)
                except Exception as e:
                    self._log(f"(ui error: {e})")
        except queue.Empty:
            pass
        self.after(200, self._drain)

    def _handle(self, kind, payload):
        if kind == "status":
            self.status_lbl.config(text=payload)
        elif kind == "def_status":
            self.def_status_var.set(payload)
        elif kind == "def_log":
            text, tag, bold = payload
            self._def_log(text, tag, bold)
        elif kind == "def_summary":
            title, lines, good = payload
            self._show_def_summary(title, lines, good)
        elif kind == "def_done":
            self._def_set_busy(False)
            self.def_status_var.set("Ready.")
        elif kind == "alert":
            data = payload if isinstance(payload, dict) else {
                "text": str(payload), "kind": "tamper"}
            text = data.get("text", "")
            tone = data.get("kind", "tamper")
            self._alerts += 1
            self.alert_lbl.config(text=f"Alerts: {self._alerts}",
                                  foreground=self.theme["warn"])
            self._log("ALERT: " + text)
            self.tamper_txt.insert("end", "• " + text + "\n")
            self.tamper_txt.see("end")
            if self.sound_on:
                play_alert(tone)
            if self.tray is not None and not self.winfo_ismapped():
                now = time.monotonic()
                if now - self._last_notify > 8.0:
                    self._last_notify = now
                    self.tray.notify(text)
        elif kind == "note":
            self._log(payload)
            self.status_lbl.config(text=payload)
        elif kind == "tray":
            if payload == "show":
                self.show_window()
            elif payload == "baseline":
                self.show_window()
                self._take_baseline()
            elif payload == "scan":
                self.show_window()
                self._scan_now()
            elif payload == "startup_toggle":
                newv = not startup_enabled()
                set_startup(newv)
                self.startup_var.set(newv)
                self._log(f"Start with Windows "
                          f"{'enabled' if newv else 'disabled'}.")
            elif payload == "exit":
                self._on_close()
        elif kind == "defender":
            self._render_defender(payload)
        elif kind == "net":
            self._net_view = payload
            self._render_network(payload)
        elif kind == "startup":
            self._render_startup(payload)
        elif kind == "scan_done":
            self.status_lbl.config(text=payload)
            self._log(payload)
        elif kind == "baseline":
            self._render_startup(payload)
            self._log("Baseline snapshot saved.")

    def _render_defender(self, st):
        t = self.def_txt
        t.config(state="normal")
        t.delete("1.0", "end")

        def yn(v):
            return "ON" if v else "OFF"

        rows = [
            ("Antivirus", st.get("AntivirusEnabled")),
            ("Real-time protection", st.get("RealTimeProtectionEnabled")),
            ("Behaviour monitoring", st.get("BehaviorMonitorEnabled")),
            ("Cloud (MAPS)", st.get("IoavProtectionEnabled")),
            ("Signature version", st.get("AntivirusSignatureVersion")),
            ("Signatures updated",
             str(st.get("AntivirusSignatureLastUpdated"))[:19]),
        ]
        for label, val in rows:
            shown = yn(val) if isinstance(val, bool) else (val or "-")
            t.insert("end", f"{label:<24}{shown}\n")
        prefs = collect_defender_prefs()
        ex = sum(len(prefs.get(k) or []) for k in (
            "ExclusionPath", "ExclusionExtension", "ExclusionProcess"))
        t.insert("end", f"{'Defender exclusions':<24}{ex}\n")
        if ex:
            t.insert("end", "  (exclusions let malware hide - review them)\n")
        t.config(state="disabled")

    def _render_network(self, conns):
        self.net_tree.delete(*self.net_tree.get_children())
        now = time.monotonic()
        for c in conns:
            proc = c.get("process", "?")
            ip = c.get("ip", "")
            key = (proc, ip)
            is_open = c.get("open", True)
            is_stuck = c.get("stuck")
            if key in self.guard.trusted:
                tag = "trusted"
            elif is_stuck:
                tag = "stuck"
            elif key not in self.guard.seen_net:
                tag = "new"
            elif not is_open:
                tag = "closed"
            else:
                tag = ""
            age = max(0.0, now - c.get("last", now))
            if age < 2:
                seen = "now"
            elif age < 60:
                seen = f"{int(age)}s ago"
            else:
                seen = f"{int(age // 60)}m ago"
            if not is_open:
                status = "Closed"
            elif is_stuck:
                status = "Blocked?"
            elif c.get("state") == "SYN_SENT":
                status = "Connecting"
            else:
                status = "Open"
            self.net_tree.insert("", "end", values=(
                proc, c.get("pid", ""), c.get("remote", ""), status, seen),
                tags=(tag,))

    def _render_startup(self, snap):
        self.start_tree.delete(*self.start_tree.get_children())
        rows = []
        for name, val in sorted(snap.get("run", {}).items()):
            rows.append(("Registry Run", name, val))
        for p in sorted(snap.get("startup", {})):
            rows.append(("Startup folder", p, ""))
        tasks = snap.get("tasks", {})
        for name in sorted(tasks)[:200]:
            rows.append(("Scheduled task", name, tasks[name]))
        for r in rows:
            self.start_tree.insert("", "end", values=r)
        self._autosize_start_columns(rows)

    def _autosize_start_columns(self, rows):
        import tkinter.font as tkfont
        fnt = tkfont.Font(font=self.F_LABEL)

        def need(idx, minw, header):
            m = fnt.measure(header)
            for r in rows:
                m = max(m, fnt.measure(str(r[idx])))
            return max(minw, m + 24)

        self.start_tree.column("type", width=need(0, 170, "Type"),
                               minwidth=120, stretch=False, anchor="w")
        self.start_tree.column("name", width=need(1, 380, "Name"),
                               minwidth=160, stretch=False, anchor="w")
        self.start_tree.column("value", width=need(2, 540, "Command / path"),
                               minwidth=200, stretch=False, anchor="w")

    def _log(self, text):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {text}"
        self.log_txt.insert("end", line + "\n")
        self.log_txt.see("end")
        append_log(line)


def main():
    start_min = any(a in ("--minimized", "--minimised", "-m")
                    for a in sys.argv[1:])
    app = DefenderPCGuardApp()
    if start_min and getattr(app, "tray", None) is not None:
        # Launch at login straight to the tray, but recorded as maximised so
        # that reopening from the tray comes back full-screen (not shifted).
        try:
            app.state("zoomed")
        except Exception:
            pass
        app.withdraw()
        try:
            app.tray.notify(APP_NAME + " is running in the notification area.")
        except Exception:
            pass
    else:
        try:
            app.state("zoomed")
        except Exception:
            app.geometry("1100x760")
    app.minsize(900, 600)
    app.protocol("WM_DELETE_WINDOW", app._on_close_request)
    app.mainloop()


if __name__ == "__main__":
    main()
