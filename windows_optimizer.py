import customtkinter as ctk
import subprocess
import os
import sys
import ctypes
import threading
import shutil
import winreg
from pathlib import Path


# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BTN_COLOR   = "#1e1e1e"
BTN_HOVER   = "#2e2e2e"

VERSION     = "1.2.0"
GITHUB_REPO = "Teddymazrin/WindowsOptimizer"  # ← update before publishing
_NO_WIN     = subprocess.CREATE_NO_WINDOW      # suppress console flash on all subprocess calls


def resource_path(relative):
    """Resolves asset paths for both .py script and PyInstaller frozen EXE."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)


# ── Admin helpers ──────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
    )
    sys.exit()


# ── Core actions ───────────────────────────────────────────────────────────────
def open_nvidia_drivers_page() -> str:
    import webbrowser
    webbrowser.open("https://www.nvidia.com/en-us/drivers/")
    return "Opened NVIDIA driver download page in browser."


def _download_file(url: str, filename: str, status_cb=None) -> str:
    import urllib.request
    downloads = Path(os.path.expanduser("~")) / "Downloads"
    downloads.mkdir(exist_ok=True)
    dest = downloads / filename

    def reporthook(count, block_size, total_size):
        if status_cb and total_size > 0:
            pct = min(100, int(count * block_size * 100 / total_size))
            status_cb(f"Downloading {filename}… {pct}%")
        elif status_cb:
            status_cb(f"Downloading {filename}…")

    urllib.request.urlretrieve(url, dest, reporthook)
    return str(dest)


def download_epic_launcher(status_cb=None) -> str:
    url = "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi"
    if status_cb:
        status_cb("Downloading Epic Games Launcher…")
    path = _download_file(url, "EpicGamesLauncherInstaller.msi", status_cb)
    os.startfile(path)
    return "Epic Games Launcher downloaded. Installer launched."


def download_steam(status_cb=None) -> str:
    url = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    path = _download_file(url, "SteamSetup.exe", status_cb)
    os.startfile(path)
    return "Steam downloaded. Installer launched."


def download_7zip(status_cb=None) -> str:
    import urllib.request, re
    if status_cb:
        status_cb("Finding latest 7-Zip version…")
    try:
        with urllib.request.urlopen("https://www.7-zip.org/download.html", timeout=10) as resp:
            html = resp.read().decode()
        match = re.search(r'href="(a/7z\d+-x64\.exe)"', html)
        url = "https://www.7-zip.org/" + match.group(1) if match else "https://www.7-zip.org/a/7z2409-x64.exe"
        filename = match.group(1).split("/")[-1] if match else "7z2409-x64.exe"
    except Exception:
        url = "https://www.7-zip.org/a/7z2409-x64.exe"
        filename = "7z2409-x64.exe"
    path = _download_file(url, filename, status_cb)
    os.startfile(path)
    return "7-Zip downloaded. Installer launched."


def download_discord(status_cb=None) -> str:
    import webbrowser
    webbrowser.open("https://discord.com/download")
    return "Opened Discord download page in browser."


def download_speccy(status_cb=None) -> str:
    url = "https://download.ccleaner.com/spsetup132.exe"
    if status_cb:
        status_cb("Downloading Speccy…")
    path = _download_file(url, "spsetup132.exe", status_cb)
    os.startfile(path)
    return "Speccy downloaded. Installer launched."


def clear_temp_files() -> str:
    dirs = [
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        r"C:\Windows\Temp",
        r"C:\Windows\Prefetch",
    ]
    removed = 0
    errors = 0
    for folder in dirs:
        if not folder or not os.path.isdir(folder):
            continue
        for item in Path(folder).iterdir():
            try:
                if item.is_file() or item.is_symlink():
                    item.unlink()
                    removed += 1
                elif item.is_dir():
                    shutil.rmtree(item)
                    removed += 1
            except Exception:
                errors += 1

    # Also flush DNS and clear icon cache
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=_NO_WIN)
    except Exception:
        pass

    return f"Done! Removed {removed} item(s). {errors} skipped (in use)."


# ── Registry helpers ────────────────────────────────────────────────────────
_HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

def _reg_set(path: str, name: str, value, vtype=None):
    hive, subkey = path.split("\\", 1)
    if vtype is None:
        vtype = winreg.REG_SZ if isinstance(value, str) else winreg.REG_DWORD
    with winreg.CreateKeyEx(_HIVES[hive], subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, name, 0, vtype, value)

def _reg_get(path: str, name: str, default=None):
    hive, subkey = path.split("\\", 1)
    try:
        with winreg.OpenKey(_HIVES[hive], subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default

def _reg_del_val(path: str, name: str):
    hive, subkey = path.split("\\", 1)
    try:
        with winreg.OpenKey(_HIVES[hive], subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteValue(k, name)
    except OSError:
        pass

def _reg_del_key(path: str):
    hive, *parts = path.split("\\")
    parent, child = "\\".join(parts[:-1]), parts[-1]
    try:
        with winreg.OpenKey(_HIVES[hive], parent, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteKey(k, child)
    except OSError:
        pass


# ── Bundle optimizations (non-optional) ─────────────────────────────────────
_GAMES = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

def apply_bundle() -> str:
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff", 1)
    _reg_set(_GAMES, "Background Only", "False")
    _reg_set(_GAMES, "Clock Rate", 10000)
    _reg_set(_GAMES, "GPU Priority", 8)
    _reg_set(_GAMES, "Priority", 6)
    _reg_set(_GAMES, "Scheduling Category", "High")
    _reg_set(_GAMES, "SFIO Priority", "Normal")
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings", "ShowSleepOption", 0)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", 1)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 0)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabledDefault", 0)
    subprocess.run(["powercfg", "-h", "off"], capture_output=True, creationflags=_NO_WIN)
    _reg_set(r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1)
    _reg_set(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", 2)
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseSpeed", "0")
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseThreshold1", "0")
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseThreshold2", "0")
    return "All optimizations applied. Some changes require a restart."

def revert_bundle() -> str:
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff", 0)
    _reg_set(_GAMES, "Background Only", "True")
    _reg_set(_GAMES, "GPU Priority", 2)
    _reg_set(_GAMES, "Priority", 2)
    _reg_set(_GAMES, "Scheduling Category", "Medium")
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings", "ShowSleepOption", 1)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", 0)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 1)
    _reg_set(r"HKLM\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabledDefault", 1)
    subprocess.run(["powercfg", "-h", "on"], capture_output=True, creationflags=_NO_WIN)
    _reg_set(r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 0)
    _reg_del_val(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana")
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseSpeed", "1")
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseThreshold1", "6")
    _reg_set(r"HKCU\Control Panel\Mouse", "MouseThreshold2", "10")
    return "Optimizations reverted. Some changes require a restart."

def bundle_applied() -> bool:
    return _reg_get(r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff", 0) == 1


# ── Optional: Disable Automatic Maintenance ──────────────────────────────────
def apply_maintenance_off() -> str:
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance", "MaintenanceDisabled", 1)
    return "Automatic maintenance disabled."

def revert_maintenance_off() -> str:
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance", "MaintenanceDisabled", 0)
    return "Automatic maintenance re-enabled."

def maintenance_off() -> bool:
    return _reg_get(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance", "MaintenanceDisabled", 0) == 1


# ── Optional: Disable Menu Show Delay ────────────────────────────────────────
def apply_menu_delay_off() -> str:
    _reg_set(r"HKCU\Control Panel\Desktop", "MenuShowDelay", "0")
    return "Menu show delay disabled."

def revert_menu_delay_off() -> str:
    _reg_set(r"HKCU\Control Panel\Desktop", "MenuShowDelay", "400")
    return "Menu show delay restored to default (400ms)."

def menu_delay_off() -> bool:
    return _reg_get(r"HKCU\Control Panel\Desktop", "MenuShowDelay", "400") == "0"


# ── Optional: Classic Context Menu (W11) ─────────────────────────────────────
_CTX_KEY = r"HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

def apply_classic_ctx() -> str:
    _reg_set(_CTX_KEY, "", "")
    return "Classic context menu enabled. Restart Explorer to apply."

def revert_classic_ctx() -> str:
    _reg_del_key(_CTX_KEY)
    return "Modern context menu restored. Restart Explorer to apply."

def classic_ctx() -> bool:
    return _reg_get(_CTX_KEY, "", None) is not None


# ── Optional: Disable Windows Widgets (W11) ──────────────────────────────────
def apply_widgets_off() -> str:
    _reg_set(r"HKLM\SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0)
    return "Windows widgets disabled."

def revert_widgets_off() -> str:
    _reg_del_val(r"HKLM\SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests")
    return "Windows widgets re-enabled."

def widgets_off() -> bool:
    return _reg_get(r"HKLM\SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 1) == 0


# ── Optional: Disable UAC ────────────────────────────────────────────────────
def apply_uac_off() -> str:
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0)
    return "UAC disabled. Restart required."

def revert_uac_off() -> str:
    _reg_set(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
    return "UAC re-enabled. Restart required."

def uac_off() -> bool:
    return _reg_get(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1) == 0


# ── Optional: High Performance Power Plan ────────────────────────────────────
_HIGH_PERF_GUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
_BALANCED_GUID  = "381b4222-f694-41f0-9685-ff5bb260df2e"
_POWER_SAVE_GUID = "a1841308-3541-4fab-bc81-f71556f20b4a"

def apply_high_perf() -> str:
    subprocess.run(["powercfg", "-restoredefaultschemes"], capture_output=True, creationflags=_NO_WIN)
    subprocess.run(["powercfg", "-SETACTIVE", _HIGH_PERF_GUID], capture_output=True, creationflags=_NO_WIN)
    subprocess.run(["powercfg", "-delete", _BALANCED_GUID], capture_output=True, creationflags=_NO_WIN)
    subprocess.run(["powercfg", "-delete", _POWER_SAVE_GUID], capture_output=True, creationflags=_NO_WIN)
    return "High Performance power plan activated."

def revert_high_perf() -> str:
    subprocess.run(["powercfg", "-restoredefaultschemes"], capture_output=True, creationflags=_NO_WIN)
    subprocess.run(["powercfg", "-SETACTIVE", _BALANCED_GUID], capture_output=True, creationflags=_NO_WIN)
    return "Power plan restored to Balanced."

def high_perf_on() -> bool:
    r = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True, text=True, creationflags=_NO_WIN)
    return _HIGH_PERF_GUID in r.stdout.lower()


# ── Optional: Disable Notifications ──────────────────────────────────────────
def apply_notif_off() -> str:
    _reg_set(r"HKCU\Software\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", 1)
    _reg_set(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", 1)
    return "Notifications disabled."

def revert_notif_off() -> str:
    _reg_del_val(r"HKCU\Software\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter")
    _reg_del_val(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter")
    return "Notifications re-enabled."

def notif_off() -> bool:
    return _reg_get(r"HKCU\Software\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", 0) == 1


# ── Optional: Disable Game Bar ────────────────────────────────────────────────
def apply_game_bar_off() -> str:
    _reg_set(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 0)
    _reg_set(r"HKCU\System\GameConfigStore", "GameDVR_Enabled", 0)
    return "Game Bar disabled."

def revert_game_bar_off() -> str:
    _reg_set(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 1)
    _reg_set(r"HKCU\System\GameConfigStore", "GameDVR_Enabled", 1)
    return "Game Bar re-enabled."

def game_bar_off() -> bool:
    return _reg_get(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 1) == 0


# ── Optional: Remove Windows Bloatware ────────────────────────────────────────
_BLOAT_APPS = [
    "Microsoft.3DBuilder",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingWeather",
    "Microsoft.GamingApp",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.MixedReality.Portal",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "MicrosoftTeams",
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Clipchamp.Clipchamp",
    "Microsoft.549981C3F5F10",  # Cortana
    "Disney.37853FC22B2CE",     # Disney+
    "SpotifyAB.SpotifyMusic",
    "BytedancePte.Ltd.TikTok",
]


def apply_remove_bloat(status_cb=None) -> str:
    """Remove all known bloatware apps via PowerShell."""
    removed = 0
    errors = 0
    total = len(_BLOAT_APPS)
    for i, app in enumerate(_BLOAT_APPS, 1):
        if status_cb:
            status_cb(f"Removing bloatware… {i}/{total}")
        # Remove for current user
        r1 = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'Get-AppxPackage -Name "{app}" | Remove-AppxPackage -ErrorAction SilentlyContinue'],
            capture_output=True, text=True, creationflags=_NO_WIN,
        )
        # Also remove the provisioned package so it doesn't reinstall for new users
        r2 = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ "{app}" '
             f'| Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue'],
            capture_output=True, text=True, creationflags=_NO_WIN,
        )
        if r1.returncode == 0 or r2.returncode == 0:
            removed += 1
        else:
            errors += 1
    return f"Bloatware removed: {removed} app(s) processed, {errors} skipped/missing."


def revert_remove_bloat(status_cb=None) -> str:
    """Reinstall all known bloatware apps from the Microsoft Store."""
    if status_cb:
        status_cb("Reinstalling bloatware apps… this may take a minute.")
    # Re-register all built-in apps from the system store
    script = (
        'Get-AppxPackage -AllUsers | ForEach-Object {'
        '  Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\\AppXManifest.xml" '
        '  -ErrorAction SilentlyContinue'
        '}'
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=300, creationflags=_NO_WIN,
    )
    return "Bloatware apps reinstalled. Some may need a restart to appear."


def bloat_removed() -> bool:
    """Check if the majority of bloat apps are gone (sample a few key ones)."""
    check = ["Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.ZuneMusic"]
    for app in check:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'if (Get-AppxPackage -Name "{app}") {{ "found" }} else {{ "gone" }}'],
            capture_output=True, text=True, creationflags=_NO_WIN,
        )
        if "found" in r.stdout:
            return False
    return True


def run_disk_cleanup() -> str:
    subprocess.Popen(["cleanmgr.exe", "/d", "C:"], creationflags=_NO_WIN)
    return "Disk Cleanup launched — select drives/categories and click OK."


def run_sfc() -> str:
    subprocess.Popen(["cmd", "/c", "sfc /scannow"], creationflags=subprocess.CREATE_NEW_CONSOLE)
    return "SFC scan started — check the console window for results (may take a few minutes)."


def run_dism() -> str:
    subprocess.Popen(
        ["cmd", "/c", "DISM /Online /Cleanup-Image /RestoreHealth"],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    return "DISM scan started — check the console window for results (may take several minutes)."


# ── Boot helpers ──────────────────────────────────────────────────────────────
def boot_to_bios() -> str:
    """Restart straight into UEFI firmware settings."""
    result = subprocess.run(
        ["shutdown", "/r", "/fw", "/t", "0"],
        capture_output=True,
        text=True,
        creationflags=_NO_WIN,
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout).strip()
        return f"Failed to restart to BIOS: {err or 'Your system may not support UEFI firmware boot.'}"
    return "Restarting into BIOS/UEFI…"


def boot_to_recovery() -> str:
    """Restart into the Windows Recovery Environment (Advanced Startup)."""
    subprocess.run(
        ["shutdown", "/r", "/o", "/t", "0"],
        creationflags=_NO_WIN,
    )
    return "Restarting into Recovery Mode…"


def boot_to_safe_mode() -> str:
    """One-time restart into Safe Mode.
    Sets bcdedit safeboot minimal, then creates a RunOnce script
    that removes the safeboot flag so the *next* reboot is normal."""
    # 1) Set Safe Mode for the next boot
    subprocess.run(
        ["bcdedit", "/set", "{current}", "safeboot", "minimal"],
        capture_output=True, creationflags=_NO_WIN,
    )
    # 2) Create a RunOnce entry that removes the safeboot flag once Safe Mode loads.
    #    The * prefix is required — without it, RunOnce entries are SKIPPED in Safe Mode.
    #    With *, Windows runs the entry even during a Safe Mode boot, then removes it.
    _reg_set(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "*RemoveSafeBoot",
        'bcdedit /deletevalue {current} safeboot',
    )
    # 3) Restart now
    subprocess.run(
        ["shutdown", "/r", "/t", "0"],
        creationflags=_NO_WIN,
    )
    return "Restarting into Safe Mode…"


def check_for_update():
    """Returns (latest_version, exe_url) or (None, None) if up to date or on error."""
    import urllib.request, json
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "windows-optimizer-updater"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        latest = data["tag_name"].lstrip("v")
        if tuple(int(x) for x in latest.split(".")) > tuple(int(x) for x in VERSION.split(".")):
            exe_url = next(
                (a["browser_download_url"] for a in data.get("assets", []) if a["name"].lower().endswith(".exe")),
                None,
            )
            return latest, exe_url
    except Exception:
        pass
    return None, None


def get_pc_specs() -> dict:
    """Collect hardware info via a single PowerShell call."""
    import json
    script = (
        "$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name;"
        "$gpu = (Get-CimInstance Win32_VideoController | Select-Object -First 1).Name;"
        "$b = Get-CimInstance Win32_BaseBoard;"
        "$board = \"$($b.Manufacturer) $($b.Product)\".Trim();"
        "$rams = @(Get-CimInstance Win32_PhysicalMemory);"
        "$total = [math]::Round(($rams | Measure-Object -Property Capacity -Sum).Sum / 1GB);"
        "$count = $rams.Count;"
        "$each = [math]::Round($total / $count);"
        "$speed = $rams[0].Speed;"
        "$ram = \"$total GB ($count x ${each}GB) @ ${speed}MHz\";"
        "[PSCustomObject]@{Motherboard=$board;GPU=$gpu;CPU=$cpu;RAM=$ram} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=20, creationflags=_NO_WIN,
    )
    data = json.loads(result.stdout.strip())
    return {k: (v or "N/A") for k, v in data.items()}


# ── GUI ────────────────────────────────────────────────────────────────────────
class WindowsOptimizer(ctk.CTk):
    def __init__(self):
        super().__init__()
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass
        self.title("Windows Optimizer")
        self.geometry("580x640")
        self.minsize(520, 500)
        self.resizable(True, True)
        self.configure(fg_color="#0a0a0a")

        self._cached_specs = None

        # If launched with --cleanup-update <path>, delete the old EXE
        if getattr(sys, "frozen", False):
            self._handle_cleanup_arg()

        self._build_ui()
        self._check_admin_banner()
        threading.Thread(target=self._prefetch_specs, daemon=True).start()
        threading.Thread(target=self._check_for_update_async, daemon=True).start()

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="#111111", corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="Windows Optimizer",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color="#ffffff",
        ).pack(pady=(8, 8))

        # ── Admin banner (filled later) ──────────────────────────────────────
        self.admin_banner = ctk.CTkLabel(
            self, text="", height=0,
            font=ctk.CTkFont(size=11),
        )
        self.admin_banner.pack(fill="x", padx=0)

        # ── Update banner (hidden until an update is found) ──────────────────
        self.update_banner = ctk.CTkFrame(self, fg_color="#0d1a2e", corner_radius=0, height=0)
        self.update_banner.pack(fill="x")
        self.update_banner.pack_propagate(False)

        # ── Tabs ─────────────────────────────────────────────────────────────
        tabs = ctk.CTkTabview(
            self,
            fg_color="#0a0a0a",
            segmented_button_fg_color="#111111",
            segmented_button_selected_color="#1e1e1e",
            segmented_button_selected_hover_color="#2a2a2a",
            segmented_button_unselected_color="#111111",
            segmented_button_unselected_hover_color="#191919",
            text_color="#aaaaaa",
            text_color_disabled="#444444",
        )
        tabs.pack(fill="both", expand=True, padx=10, pady=(0, 0))
        tabs.add("Optimizations")
        tabs.add("Downloads")
        tabs.add("Maintenance")
        tabs.add("Boot")

        # ── Optimizations tab ────────────────────────────────────────────────
        opt_frame = ctk.CTkScrollableFrame(tabs.tab("Optimizations"), fg_color="transparent")
        opt_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self._make_toggle_card(
            opt_frame,
            title="Apply All Optimizations",
            desc="Disables power throttling, sleep, hibernate, Fast Startup, Cortana, "
                 "background apps, and tunes game scheduling & mouse precision.",
            is_on=bundle_applied(),
            apply_fn=apply_bundle,
            revert_fn=revert_bundle,
        )

        ctk.CTkLabel(
            opt_frame,
            text="OPTIONAL",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#444444",
            anchor="w",
        ).pack(anchor="w", padx=4, pady=(10, 2))

        self._make_toggle_card(
            opt_frame,
            title="Disable Automatic Maintenance",
            desc="Stops Windows from running automatic background maintenance tasks.",
            is_on=maintenance_off(),
            apply_fn=apply_maintenance_off,
            revert_fn=revert_maintenance_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="Disable Menu Show Delay",
            desc="Removes the 400ms delay before context menus appear.",
            is_on=menu_delay_off(),
            apply_fn=apply_menu_delay_off,
            revert_fn=revert_menu_delay_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="Classic Context Menu  (W11)",
            desc="Restores the full right-click context menu instead of the shortened W11 version.",
            is_on=classic_ctx(),
            apply_fn=apply_classic_ctx,
            revert_fn=revert_classic_ctx,
        )

        self._make_toggle_card(
            opt_frame,
            title="Disable Windows Widgets  (W11)",
            desc="Removes the News & Interests / Widgets panel from the taskbar.",
            is_on=widgets_off(),
            apply_fn=apply_widgets_off,
            revert_fn=revert_widgets_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="Disable UAC",
            desc="Turns off User Account Control elevation prompts. Requires restart.",
            is_on=uac_off(),
            apply_fn=apply_uac_off,
            revert_fn=revert_uac_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="High Performance Power Plan",
            desc="Activates High Performance mode and removes Balanced/Power Saver plans.",
            is_on=high_perf_on(),
            apply_fn=apply_high_perf,
            revert_fn=revert_high_perf,
        )

        self._make_toggle_card(
            opt_frame,
            title="Disable Notifications",
            desc="Hides the notification center and all toast notifications.",
            is_on=notif_off(),
            apply_fn=apply_notif_off,
            revert_fn=revert_notif_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="Disable Game Bar",
            desc="Disables Xbox Game Bar and Game DVR background capture.",
            is_on=game_bar_off(),
            apply_fn=apply_game_bar_off,
            revert_fn=revert_game_bar_off,
        )

        self._make_toggle_card(
            opt_frame,
            title="Remove Windows Bloatware",
            desc="Uninstalls pre-installed apps like Bing News, Solitaire, Xbox, Cortana, "
                 "Teams, Clipchamp, and more. Toggle off to reinstall them.",
            is_on=bloat_removed(),
            apply_fn=apply_remove_bloat,
            revert_fn=revert_remove_bloat,
        )

        # ── Downloads tab ────────────────────────────────────────────────────
        dl_frame = ctk.CTkScrollableFrame(tabs.tab("Downloads"), fg_color="transparent")
        dl_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self._make_card(
            dl_frame,
            title="NVIDIA Drivers",
            desc="Open the NVIDIA website to download the latest graphics drivers for your GPU.",
            btn_text="Download NVIDIA Drivers",
            action=open_nvidia_drivers_page,
        )

        self._make_card(
            dl_frame,
            title="Epic Games Launcher",
            desc="Download and install the Epic Games Launcher directly.",
            btn_text="Download Epic Launcher",
            action=download_epic_launcher,
        )

        self._make_card(
            dl_frame,
            title="Steam",
            desc="Download and install Steam, the leading PC gaming platform by Valve.",
            btn_text="Download Steam",
            action=download_steam,
        )

        self._make_card(
            dl_frame,
            title="7-Zip",
            desc="Download and install 7-Zip, a free open-source file archiver.",
            btn_text="Download 7-Zip",
            action=download_7zip,
        )

        self._make_card(
            dl_frame,
            title="Discord",
            desc="Download and install Discord, the popular voice and text chat app.",
            btn_text="Download Discord",
            action=download_discord,
        )

        self._make_card(
            dl_frame,
            title="Speccy",
            desc="Download Speccy by CCleaner — a detailed system information and hardware specs tool.",
            btn_text="Download Speccy",
            action=download_speccy,
        )

        # ── Maintenance tab ──────────────────────────────────────────────────
        maint_tab = tabs.tab("Maintenance")

        # Cards view (default)
        self._maint_cards_frame = ctk.CTkScrollableFrame(maint_tab, fg_color="transparent")
        self._maint_cards_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self._make_card(
            self._maint_cards_frame,
            title="System File Check",
            desc="Scan for and repair corrupted Windows system files using sfc /scannow.",
            btn_text="Run SFC Scan",
            action=run_sfc,
        )

        self._make_card(
            self._maint_cards_frame,
            title="DISM Scan",
            desc="Repair the Windows component store using DISM /RestoreHealth.",
            btn_text="Run DISM Scan",
            action=run_dism,
        )

        self._make_card(
            self._maint_cards_frame,
            title="Clear Temp Files",
            desc="Remove temporary files from %TEMP%, C:\\Windows\\Temp, and Prefetch.",
            btn_text="Clear Temp Files",
            action=clear_temp_files,
        )

        self._make_card(
            self._maint_cards_frame,
            title="Disk Cleanup",
            desc="Launch Windows Disk Cleanup to free up space from system and junk files.",
            btn_text="Run Disk Cleanup",
            action=run_disk_cleanup,
        )

        # ── Boot tab ─────────────────────────────────────────────────────────
        boot_frame = ctk.CTkScrollableFrame(tabs.tab("Boot"), fg_color="transparent")
        boot_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self._make_card(
            boot_frame,
            title="Boot into BIOS / UEFI",
            desc="Restart your PC directly into the UEFI firmware settings (BIOS).",
            btn_text="Restart to BIOS",
            action=boot_to_bios,
        )

        self._make_card(
            boot_frame,
            title="Boot into Recovery Mode",
            desc="Restart into Windows Recovery Environment (Advanced Startup Options).",
            btn_text="Restart to Recovery",
            action=boot_to_recovery,
        )

        self._make_card(
            boot_frame,
            title="Boot into Safe Mode",
            desc="One-time restart into Safe Mode. The next restart after that returns to normal Windows.",
            btn_text="Restart to Safe Mode",
            action=boot_to_safe_mode,
        )

        # ── Footer (status + specs in a compact 2-row bar) ────────────
        footer = ctk.CTkFrame(self, fg_color="#111111", corner_radius=0)
        footer.pack(fill="x", side="bottom")

        footer_inner = ctk.CTkFrame(footer, fg_color="transparent")
        footer_inner.pack(fill="x", padx=12, pady=(4, 5))

        # Row 1: status (left) + CPU · GPU (right)
        row1 = ctk.CTkFrame(footer_inner, fg_color="transparent")
        row1.pack(fill="x")

        self.status_var = ctk.StringVar(value="Ready.")
        ctk.CTkLabel(
            row1,
            textvariable=self.status_var,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#555555",
            anchor="w",
        ).pack(side="left")

        self._spec_row1 = ctk.CTkLabel(
            row1, text="",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#444444",
            anchor="e",
        )
        self._spec_row1.pack(side="right")

        # Row 2: RAM · Motherboard (right-aligned)
        row2 = ctk.CTkFrame(footer_inner, fg_color="transparent")
        row2.pack(fill="x")

        self._spec_row2 = ctk.CTkLabel(
            row2, text="",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#444444",
            anchor="e",
        )
        self._spec_row2.pack(side="right")

    def _make_card(self, parent, title, desc, btn_text, action=None, command=None):
        card = ctk.CTkFrame(parent, fg_color="#141414", corner_radius=10)
        card.pack(fill="x", pady=6)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=14)

        # Left: text
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            left, text=title,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            left, text=desc,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#555555",
            justify="left",
            anchor="w",
            wraplength=300,
        ).pack(anchor="w", pady=(4, 0))

        # Right: button
        cmd = command if command is not None else (lambda a=action: self._run(a))
        btn = ctk.CTkButton(
            inner,
            text=btn_text,
            width=190,
            height=38,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=BTN_COLOR,
            hover_color=BTN_HOVER,
            text_color="#ffffff",
            border_width=1,
            border_color="#2e2e2e",
            corner_radius=8,
            command=cmd,
        )
        btn.pack(side="right", padx=(12, 0))

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _check_admin_banner(self):
        if not is_admin():
            self.admin_banner.configure(
                text="  Not running as Administrator — some features may be limited.",
                text_color="#ffaa00",
                fg_color="#1a1500",
                height=28,
            )

    def _run(self, action):
        """Run an action in a background thread so the UI stays responsive."""
        import inspect
        self.status_var.set("Working…")

        def status_cb(msg):
            self.after(0, lambda m=msg: self.status_var.set(m))

        accepts_cb = "status_cb" in inspect.signature(action).parameters

        def worker():
            try:
                msg = action(status_cb=status_cb) if accepts_cb else action()
            except Exception as e:
                msg = f"Error: {e}"
            self.after(0, lambda: self.status_var.set(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _make_toggle_card(self, parent, title, desc, is_on, apply_fn, revert_fn):
        card = ctk.CTkFrame(parent, fg_color="#141414", corner_radius=10)
        card.pack(fill="x", pady=6)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=14)

        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            left, text=title,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            left, text=desc,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#555555",
            justify="left",
            anchor="w",
            wraplength=340,
        ).pack(anchor="w", pady=(4, 0))

        switch = ctk.CTkSwitch(
            inner, text="",
            progress_color="#1a6b35",
            button_color="#cccccc",
            button_hover_color="#ffffff",
            fg_color="#2e2e2e",
        )
        switch.pack(side="right", padx=(16, 0))
        if is_on:
            switch.select()
        switch.configure(command=lambda s=switch, a=apply_fn, r=revert_fn: self._run_toggle(s, a, r))

    def _run_toggle(self, switch, apply_fn, revert_fn):
        fn = apply_fn if switch.get() else revert_fn
        self._run(fn)

    def _handle_cleanup_arg(self):
        """If launched with --cleanup-update <old_path>, delete the old EXE in background."""
        try:
            if "--cleanup-update" in sys.argv:
                idx = sys.argv.index("--cleanup-update")
                old_path = sys.argv[idx + 1]
                threading.Thread(
                    target=self._delete_old_exe,
                    args=(old_path,),
                    daemon=True,
                ).start()
        except (IndexError, ValueError):
            pass

    @staticmethod
    def _delete_old_exe(old_path):
        """Retry deleting the old EXE for up to ~15 seconds (file may still be locked)."""
        import time
        for _ in range(30):
            try:
                if os.path.exists(old_path):
                    os.remove(old_path)
                return  # deleted or already gone
            except PermissionError:
                time.sleep(0.5)
            except Exception:
                return

    def _prefetch_specs(self):
        try:
            specs = get_pc_specs()
            self._cached_specs = specs
            line1 = "CPU: {CPU}  ·  GPU: {GPU}".format(**specs)
            line2 = "RAM: {RAM}  ·  Board: {Motherboard}".format(**specs)
            self.after(0, lambda: self._spec_row1.configure(text=line1))
            self.after(0, lambda: self._spec_row2.configure(text=line2))
        except Exception:
            pass

    # ── Auto-update ────────────────────────────────────────────────────────────
    def _check_for_update_async(self):
        latest, url = check_for_update()
        if latest:
            self.after(0, lambda: self._show_update_banner(latest, url))

    def _show_update_banner(self, latest, url):
        inner = ctk.CTkFrame(self.update_banner, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14)

        ctk.CTkLabel(
            inner,
            text=f"Update available: v{latest}  —  current: v{VERSION}",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#5bb3f5",
            anchor="w",
        ).pack(side="left")

        ctk.CTkButton(
            inner,
            text="Update Now",
            width=110,
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1a4a7a",
            hover_color="#1d5a99",
            text_color="#ffffff",
            border_width=1,
            border_color="#2a5a8a",
            corner_radius=6,
            command=lambda: self._start_update(url, latest),
        ).pack(side="right", pady=6)

        self.update_banner.configure(height=38)

    def _start_update(self, url, latest):
        import webbrowser
        # If no EXE asset or running as a raw .py script, just open the releases page
        if not url or not getattr(sys, "frozen", False):
            webbrowser.open(f"https://github.com/{GITHUB_REPO}/releases/latest")
            return

        def worker():
            new_exe = None
            try:
                import urllib.request
                self.after(0, lambda: self.status_var.set(f"Downloading v{latest}…"))

                current_exe = sys.executable
                exe_dir     = os.path.dirname(current_exe)
                exe_name    = os.path.basename(current_exe)
                new_exe     = os.path.join(exe_dir, exe_name + ".new")

                # ── 1. Download new EXE ──────────────────────────────────
                def reporthook(count, block, total):
                    if total > 0:
                        pct = min(100, int(count * block * 100 / total))
                        self.after(0, lambda p=pct: self.status_var.set(f"Downloading update… {p}%"))

                urllib.request.urlretrieve(url, new_exe, reporthook)

                if os.path.getsize(new_exe) < 1_000_000:
                    raise RuntimeError("Downloaded file is too small — update aborted.")

                self.after(0, lambda: self.status_var.set("Applying update…"))

                # ── 2. Write a .ps1 script to disk ───────────────────────
                current_pid = os.getpid()
                temp_dir    = os.environ.get("TEMP", exe_dir)
                ps1_path    = os.path.join(temp_dir, "_wo_update.ps1")

                ps_script = f'''
# Wait for the old process to exit
try {{
    $proc = Get-Process -Id {current_pid} -ErrorAction Stop
    $proc.WaitForExit()
}} catch {{
    # Process already exited
}}

Start-Sleep -Seconds 2

# Retry deleting old EXE (file may be locked briefly)
for ($i = 0; $i -lt 30; $i++) {{
    try {{
        if (Test-Path '{current_exe}') {{
            Remove-Item -Path '{current_exe}' -Force -ErrorAction Stop
        }}
        break
    }} catch {{
        Start-Sleep -Milliseconds 500
    }}
}}

# Rename .new to original name
if (-not (Test-Path '{current_exe}')) {{
    Move-Item -Path '{new_exe}' -Destination '{current_exe}' -Force
}}

# Launch the updated EXE
Start-Process -FilePath '{current_exe}'

# Clean up this script
Remove-Item -Path '{ps1_path}' -Force -ErrorAction SilentlyContinue
'''
                with open(ps1_path, "w", encoding="utf-8") as f:
                    f.write(ps_script)

                # ── 3. Launch .ps1 via a new hidden powershell process ───
                #    Using WMI to create a truly independent process that
                #    is not a child of this app.
                wmi_cmd = (
                    f'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass '
                    f'-File "{ps1_path}"'
                )
                subprocess.Popen(
                    [
                        "wmic", "process", "call", "create",
                        wmi_cmd,
                    ],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )

                # ── 4. Exit the current app ──────────────────────────────
                self.after(0, lambda: self.status_var.set("Restarting…"))
                self.after(1000, lambda: os._exit(0))

            except Exception as e:
                if new_exe and os.path.exists(new_exe):
                    try:
                        os.remove(new_exe)
                    except Exception:
                        pass
                self.after(0, lambda: self.status_var.set(f"Update failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Auto-elevate on Windows if not already admin
    if sys.platform == "win32" and not is_admin():
        relaunch_as_admin()

    app = WindowsOptimizer()
    app.mainloop()