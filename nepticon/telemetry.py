"""Dependency-free telemetry collection for Nepticon agents.

The agent deliberately avoids psutil and other native extensions.  It uses
the standard library plus ``ctypes`` Win32 calls, ``/proc`` on Linux and
``shutil.disk_usage`` where available, so a stock Python installation is
enough to run on a fleet node.
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import getpass
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_DARWIN = sys.platform == "darwin"

SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Win32 structures
# ---------------------------------------------------------------------------

if IS_WINDOWS:  # pragma: no branch - definitions are harmless either way
    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    class _IP_ADDR_STRING(ctypes.Structure):
        pass

    _IP_ADDR_STRING._fields_ = [
        ("Next", ctypes.POINTER(_IP_ADDR_STRING)),
        ("IpAddress", ctypes.c_char * 16),
        ("IpMask", ctypes.c_char * 16),
        ("Context", ctypes.c_ulong),
    ]

    class IP_ADAPTER_INFO(ctypes.Structure):
        pass

    IP_ADAPTER_INFO._fields_ = [
        ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex", ctypes.c_ulong),
        ("AdapterName", ctypes.c_char * 260),
        ("Description", ctypes.c_char * 132),
        ("AddressLength", ctypes.c_uint),
        ("Address", ctypes.c_ubyte * 8),
        ("Index", ctypes.c_ulong),
        ("Type", ctypes.c_uint),
        ("DhcpEnabled", ctypes.c_uint),
        ("CurrentIpAddress", ctypes.POINTER(_IP_ADDR_STRING)),
        ("IpAddressList", _IP_ADDR_STRING),
        ("GatewayList", _IP_ADDR_STRING),
        ("DhcpServer", _IP_ADDR_STRING),
        ("HaveWins", ctypes.c_int),
        ("PrimaryWinsServer", _IP_ADDR_STRING),
        ("SecondaryWinsServer", _IP_ADDR_STRING),
        ("LeaseObtained", ctypes.c_ulong),
        ("LeaseExpires", ctypes.c_ulong),
    ]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _round(value: float, digits: int = 2) -> float:
    return round(float(value), digits)


def _utc_iso(timestamp: Optional[float] = None) -> str:
    moment = _dt.datetime.fromtimestamp(
        time.time() if timestamp is None else timestamp, tz=_dt.timezone.utc
    )
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def privilege_level() -> str:
    """Return ``admin`` when the process has elevated rights, else ``user``."""

    try:
        if IS_WINDOWS:
            return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
        return "admin" if os.geteuid() == 0 else "user"
    except Exception:
        return "user"


def _cpu_times() -> Optional[tuple[int, int]]:
    """Return ``(idle, total)`` jiffies/ticks or ``None`` if unavailable."""

    try:
        if IS_WINDOWS:
            idle = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            if not ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
            ):
                return None
            idle_ticks = (idle.dwHighDateTime << 32) | idle.dwLowDateTime
            kernel_ticks = (kernel.dwHighDateTime << 32) | kernel.dwLowDateTime
            user_ticks = (user.dwHighDateTime << 32) | user.dwLowDateTime
            return idle_ticks, kernel_ticks + user_ticks
        if IS_LINUX:
            with open("/proc/stat", "r", encoding="utf-8") as handle:
                line = handle.readline()
            fields = [int(value) for value in line.split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            return idle, sum(fields[:8])
    except (OSError, ValueError, IndexError, ZeroDivisionError):
        return None
    return None


def _load_average() -> Optional[List[float]]:
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (AttributeError, OSError):
        return None


def _memory_info() -> Dict[str, Any]:
    if IS_WINDOWS:
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            total = int(status.ullTotalPhys)
            available = int(status.ullAvailPhys)
            used = total - available
            return {
                "total_mb": round(total / (1024 * 1024), 1),
                "used_mb": round(used / (1024 * 1024), 1),
                "free_mb": round(available / (1024 * 1024), 1),
                "percent": _round(used / total * 100 if total else 0.0, 1),
            }
    elif IS_LINUX:
        values: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"^(\w+):\s+(\d+)\s+kB", line)
                if match:
                    values[match.group(1)] = int(match.group(2)) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable")
        if available is None:
            available = (
                values.get("MemFree", 0)
                + values.get("Buffers", 0)
                + values.get("Cached", 0)
            )
        used = max(0, total - available)
        return {
            "total_mb": round(total / (1024 * 1024), 1),
            "used_mb": round(used / (1024 * 1024), 1),
            "free_mb": round(available / (1024 * 1024), 1),
            "percent": _round(used / total * 100 if total else 0.0, 1),
        }
    elif IS_DARWIN:
        try:
            total = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
            vm = subprocess.check_output(["vm_stat"], text=True)
            match = re.search(r"page size of (\d+) bytes", vm)
            page = int(match.group(1)) if match else 4096
            pages = dict(re.findall(r"([A-Za-z ]+):\s+(\d+)", vm))
            free = int(pages.get("Pages free", 0)) * page
            inactive = int(pages.get("Pages inactive", 0)) * page
            available = free + inactive
            used = max(0, total - available)
            return {
                "total_mb": round(total / (1024 * 1024), 1),
                "used_mb": round(used / (1024 * 1024), 1),
                "free_mb": round(available / (1024 * 1024), 1),
                "percent": _round(used / total * 100 if total else 0.0, 1),
            }
        except Exception:
            pass
    try:
        total = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        available = os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        used = total - available
        return {
            "total_mb": round(total / (1024 * 1024), 1),
            "used_mb": round(used / (1024 * 1024), 1),
            "free_mb": round(available / (1024 * 1024), 1),
            "percent": _round(used / total * 100 if total else 0.0, 1),
        }
    except (AttributeError, ValueError, OSError):
        return {"total_mb": 0.0, "used_mb": 0.0, "free_mb": 0.0, "percent": 0.0}


def _disk_info() -> Dict[str, Any]:
    root = os.path.abspath(os.sep)
    usage = shutil.disk_usage(root)
    total = usage.total or 1
    return {
        "mount": root,
        "total_gb": _round(usage.total / (1024**3), 2),
        "used_gb": _round(usage.used / (1024**3), 2),
        "free_gb": _round(usage.free / (1024**3), 2),
        "percent": _round(usage.used / total * 100, 1),
    }


def _uptime_seconds() -> float:
    try:
        if IS_WINDOWS:
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            ticks = kernel32.GetTickCount64()
            return float(ticks) / 1000.0
        if IS_LINUX:
            with open("/proc/uptime", "r", encoding="ascii") as handle:
                return float(handle.read().split()[0])
        if IS_DARWIN:
            output = subprocess.check_output(["sysctl", "-n", "kern.boottime"], text=True)
            match = re.search(r"sec\s*=\s*(\d+)", output)
            if match:
                return max(0.0, time.time() - int(match.group(1)))
    except Exception:
        pass
    return 0.0


def _network_interfaces() -> List[Dict[str, Any]]:
    if IS_WINDOWS:
        return _windows_network()
    if IS_LINUX:
        return _linux_network()
    return _generic_network()


def _windows_network() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        size = ctypes.c_ulong(0)
        iphlpapi.GetAdaptersInfo(None, ctypes.byref(size))
        if size.value == 0:
            return _generic_network()
        buffer = ctypes.create_string_buffer(size.value)
        result = iphlpapi.GetAdaptersInfo(
            ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_INFO)),
            ctypes.byref(size),
        )
        if result != 0:
            return _generic_network()
        adapter = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_INFO))
        while adapter:
            info = adapter.contents
            description = info.Description.decode("mbcs", errors="replace").strip()
            adapter_name = info.AdapterName.decode("mbcs", errors="replace").strip()
            mac = ":".join(f"{byte:02X}" for byte in info.Address[: info.AddressLength])
            gateway = info.GatewayList.IpAddress.decode("ascii", errors="ignore").strip()
            address = info.IpAddressList
            while True:
                ip = address.IpAddress.decode("ascii", errors="ignore").strip()
                mask = address.IpMask.decode("ascii", errors="ignore").strip()
                if ip and ip != "0.0.0.0":
                    entries.append(
                        {
                            "name": description or adapter_name or "adapter",
                            "id": adapter_name,
                            "address": ip,
                            "netmask": mask,
                            "mac": mac,
                            "gateway": gateway,
                            "state": "up",
                        }
                    )
                if not address.Next:
                    break
                address = address.Next.contents
            adapter = info.Next
    except Exception:
        return _generic_network()
    return entries or _generic_network()


def _linux_network() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        import fcntl
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _, name in socket.if_nameindex():
                address = ""
                netmask = ""
                try:
                    request = struct.pack("256s", name[:15].encode("utf-8"))
                    response = fcntl.ioctl(sock.fileno(), 0x8915, request)  # SIOCGIFADDR
                    address = socket.inet_ntoa(response[20:24])
                except OSError:
                    pass
                try:
                    request = struct.pack("256s", name[:15].encode("utf-8"))
                    response = fcntl.ioctl(sock.fileno(), 0x891B, request)  # SIOCGIFNETMASK
                    netmask = socket.inet_ntoa(response[20:24])
                except OSError:
                    pass
                mac = ""
                state = "unknown"
                try:
                    mac = Path(f"/sys/class/net/{name}/address").read_text().strip()
                    state = Path(f"/sys/class/net/{name}/operstate").read_text().strip()
                except OSError:
                    pass
                entries.append(
                    {
                        "name": name,
                        "id": name,
                        "address": address,
                        "netmask": netmask,
                        "mac": mac,
                        "gateway": "",
                        "state": state or ("up" if address else "down"),
                    }
                )
        finally:
            sock.close()
    except Exception:
        return _generic_network()
    return entries


def _generic_network() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    seen: set[str] = set()
    try:
        names = [name for _, name in socket.if_nameindex()]
    except OSError:
        names = []
    try:
        host_addresses = {
            info[4][0]
            for info in socket.getaddrinfo(socket.gethostname(), None)
            if info[4] and info[4][0]
        }
    except OSError:
        host_addresses = set()
    for name in names or ["host"]:
        entries.append(
            {
                "name": name,
                "id": name,
                "address": "",
                "netmask": "",
                "mac": "",
                "gateway": "",
                "state": "up",
            }
        )
    for address in sorted(host_addresses):
        if address in seen:
            continue
        seen.add(address)
        entries.append(
            {
                "name": "host",
                "id": "host",
                "address": address,
                "netmask": "",
                "mac": "",
                "gateway": "",
                "state": "up",
            }
        )
    return entries


def _windows_processes(limit: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
        ctypes.c_ulong,
    ]
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if not snapshot or snapshot == invalid_handle:
        return results
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return results
        while True:
            pid = int(entry.th32ProcessID)
            rss = 0
            threads = int(entry.cntThreads)
            process = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
            if not process:
                process = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
            if process:
                try:
                    counters = PROCESS_MEMORY_COUNTERS()
                    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                    if psapi.GetProcessMemoryInfo(
                        process, ctypes.byref(counters), counters.cb
                    ):
                        rss = int(counters.WorkingSetSize)
                except Exception:
                    pass
                finally:
                    kernel32.CloseHandle(process)
            results.append(
                {
                    "pid": pid,
                    "ppid": int(entry.th32ParentProcessID),
                    "name": entry.szExeFile,
                    "rss_mb": _round(rss / (1024 * 1024), 1),
                    "threads": threads,
                    "state": "running",
                }
            )
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return results


def _linux_processes(limit: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    page_size = os.sysconf("SC_PAGE_SIZE")
    try:
        candidates = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return results
    for name in candidates:
        try:
            stat = Path(f"/proc/{name}/stat").read_text(encoding="utf-8")
            open_paren = stat.find("(")
            close_paren = stat.rfind(")")
            if open_paren < 0 or close_paren < 0:
                continue
            process_name = stat[open_paren + 1 : close_paren]
            fields = stat[close_paren + 2 :].split()
            rss_pages = int(fields[21])
            results.append(
                {
                    "pid": int(name),
                    "ppid": int(fields[1]),
                    "name": process_name,
                    "rss_mb": _round(rss_pages * page_size / (1024 * 1024), 1),
                    "threads": int(fields[17]),
                    "state": fields[0],
                }
            )
        except (OSError, ValueError, IndexError):
            continue
    return results


def _darwin_processes(limit: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss=,comm="], text=True, timeout=10
        )
    except Exception:
        return results
    for line in output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        try:
            results.append(
                {
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "name": parts[3].strip(),
                    "rss_mb": _round(int(parts[2]) / 1024, 1),
                    "threads": 0,
                    "state": "running",
                }
            )
        except ValueError:
            continue
    return results


def _processes(limit: int = 25) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 500))
    try:
        if IS_WINDOWS:
            results = _windows_processes(limit)
        elif IS_LINUX:
            results = _linux_processes(limit)
        elif IS_DARWIN:
            results = _darwin_processes(limit)
        else:
            results = []
    except Exception:
        results = []
    results.sort(key=lambda item: item.get("rss_mb", 0), reverse=True)
    return results[:limit]


def _runtime_context() -> List[Dict[str, str]]:
    services: List[Dict[str, str]] = []

    def add(name: str, state: str, detail: str = "") -> None:
        services.append({"name": name, "state": state, "detail": detail})

    if IS_LINUX:
        try:
            init = Path("/proc/1/comm").read_text().strip()
        except OSError:
            init = "unknown"
        add("init", "active" if init != "unknown" else "unknown", init)
        add(
            "systemd",
            "active" if Path("/run/systemd/system").is_dir() else "absent",
            "/run/systemd/system",
        )
        try:
            cgroup = Path("/proc/1/cgroup").read_text(errors="ignore")
        except OSError:
            cgroup = ""
        container = (
            Path("/.dockerenv").exists()
            or Path("/run/.containerenv").exists()
            or any(
                keyword in cgroup
                for keyword in ("docker", "kubepods", "lxc", "containerd")
            )
        )
        add("container", "active" if container else "absent", "docker/containerd markers")
    elif IS_WINDOWS:
        scm = "unknown"
        try:
            advapi32 = ctypes.WinDLL("advapi32")
            advapi32.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
            advapi32.OpenSCManagerW.restype = ctypes.c_void_p
            advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]
            advapi32.CloseServiceHandle.restype = ctypes.c_int
            handle = advapi32.OpenSCManagerW(None, None, 0x0001)
            if handle:
                scm = "active"
                advapi32.CloseServiceHandle(handle)
        except Exception:
            scm = "unavailable"
        add("service-control-manager", scm, "Windows SCM")
        add(
            "wsl",
            "active" if "microsoft" in platform.release().lower() else "absent",
            platform.platform() if "microsoft" in platform.release().lower() else "Windows host",
        )
    elif IS_DARWIN:
        add("launchd", "active", "macOS init")
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"):
        add("ssh-session", "active", os.environ.get("SSH_CONNECTION", "SSH_CLIENT set"))
    else:
        add("ssh-session", "absent", "no SSH_CONNECTION")
    if os.environ.get("VIRTUAL_ENV"):
        add("virtualenv", "active", os.environ["VIRTUAL_ENV"])
    nepticon_vars = sum(1 for key in os.environ if key.startswith("NEPTICON_"))
    add("nepticon-env", "active" if nepticon_vars else "absent", f"{nepticon_vars} variable(s)")
    return services


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class Telemetry:
    """Stateful collector; the CPU sampler needs two samples for a delta."""

    def __init__(self) -> None:
        self.started_at = time.time()
        self._started_monotonic = time.monotonic()
        self._cpu_lock = threading.Lock()
        self._last_cpu = _cpu_times()
        self._last_cpu_at = time.monotonic()

    @property
    def agent_uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._started_monotonic)

    def cpu_percent(self, minimum_interval: float = 0.15) -> float:
        with self._cpu_lock:
            current = _cpu_times()
            now = time.monotonic()
            if current is None:
                return 0.0
            if self._last_cpu is None:
                self._last_cpu = current
                self._last_cpu_at = now
                return 0.0
            elapsed = now - self._last_cpu_at
            if elapsed < minimum_interval:
                time.sleep(minimum_interval - elapsed)
                current = _cpu_times()
                now = time.monotonic()
                if current is None:
                    return 0.0
            idle_delta = current[0] - self._last_cpu[0]
            total_delta = current[1] - self._last_cpu[1]
            self._last_cpu = current
            self._last_cpu_at = now
            if total_delta <= 0:
                return 0.0
            percent = (1.0 - idle_delta / total_delta) * 100.0
            return _round(max(0.0, min(100.0, percent)), 1)

    def memory(self) -> Dict[str, Any]:
        try:
            return _memory_info()
        except Exception:
            return {"total_mb": 0.0, "used_mb": 0.0, "free_mb": 0.0, "percent": 0.0}

    def disk(self) -> Dict[str, Any]:
        try:
            return _disk_info()
        except Exception:
            return {
                "mount": os.path.abspath(os.sep),
                "total_gb": 0.0,
                "used_gb": 0.0,
                "free_gb": 0.0,
                "percent": 0.0,
            }

    def uptime(self) -> float:
        return _uptime_seconds()

    def network(self) -> List[Dict[str, Any]]:
        try:
            return _network_interfaces()
        except Exception:
            return []

    def health(self) -> Dict[str, Any]:
        errors: List[str] = []
        try:
            cpu_percent = self.cpu_percent()
        except Exception as exc:
            cpu_percent = 0.0
            errors.append(f"cpu: {exc}")
        try:
            memory = self.memory()
        except Exception as exc:
            memory = {}
            errors.append(f"memory: {exc}")
        try:
            disk = self.disk()
        except Exception as exc:
            disk = {}
            errors.append(f"disk: {exc}")
        try:
            uptime = self.uptime()
        except Exception as exc:
            uptime = 0.0
            errors.append(f"uptime: {exc}")
        try:
            network = self.network()
        except Exception as exc:
            network = []
            errors.append(f"network: {exc}")
        return {
            "sampled_at": _utc_iso(),
            "hostname": socket.gethostname(),
            "cpu": {
                "cores": os.cpu_count() or 1,
                "percent": cpu_percent,
                "load": _load_average(),
            },
            "memory": memory,
            "disk": disk,
            "uptime_seconds": _round(uptime, 1),
            "python_version": platform.python_version(),
            "os_info": platform.platform(),
            "arch": platform.machine(),
            "privilege_level": privilege_level(),
            "network": network,
            "agent_uptime_seconds": _round(self.agent_uptime_seconds, 1),
            "errors": errors,
        }

    def sysinfo(self) -> Dict[str, Any]:
        boot = time.time() - self.uptime()
        return {
            "hostname": socket.gethostname(),
            "os_info": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
            "cpu_cores": os.cpu_count() or 1,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "python_executable": sys.executable,
            "user": getpass.getuser(),
            "pid": os.getpid(),
            "privilege_level": privilege_level(),
            "cwd": os.getcwd(),
            "boot_time": _utc_iso(boot) if boot > 0 else None,
            "uptime_seconds": _round(self.uptime(), 1),
            "agent_uptime_seconds": _round(self.agent_uptime_seconds, 1),
            "agent_started_at": _utc_iso(self.started_at),
        }

    def processes(self, limit: int = 25) -> Dict[str, Any]:
        processes = _processes(limit)
        return {
            "count": len(processes),
            "limit": limit,
            "processes": processes,
            "sampled_at": _utc_iso(),
        }

    def environment(self) -> Dict[str, Any]:
        variables: List[Dict[str, str]] = []
        redacted = 0
        for name in sorted(os.environ):
            value = os.environ[name]
            if SECRET_NAME.search(name):
                value = "***redacted***"
                redacted += 1
            variables.append({"name": name, "value": value})
        return {
            "count": len(variables),
            "redacted": redacted,
            "variables": variables,
            "services": _runtime_context(),
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "executable": sys.executable,
                "prefix": sys.prefix,
                "virtualenv": os.environ.get("VIRTUAL_ENV", ""),
            },
            "cwd": os.getcwd(),
            "pid": os.getpid(),
            "sampled_at": _utc_iso(),
        }
