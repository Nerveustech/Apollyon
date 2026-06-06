from platform import (
    processor,
    node,
    system,
    version,
    release,
    platform
)
from os import name, cpu_count
from os.path import exists
from getpass import getuser
import ctypes


def _get_cpu_name() -> str:
    """Get the friendly CPU name from OS-specific sources.
    
    Returns a human-readable CPU name like '11th Gen Intel(R) Core(TM) i5-11400F'
    instead of the raw processor string.
    Supports Windows, Linux, macOS, and WSL.
    """
    # Try Windows Registry first for the friendly CPU name
    if name == "nt":
        try:
            from winreg import OpenKey, HKEY_LOCAL_MACHINE, QueryValueEx, CloseKey
            key = OpenKey(
                HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            value, _ = QueryValueEx(key, "ProcessorNameString")
            CloseKey(key)
            if value and value.strip():
                return value.strip()
        except (OSError, FileNotFoundError):
            pass

    # Try Linux /proc/cpuinfo (works on Linux and WSL)
    if exists("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("name"):
                        # Format: "name : Intel(R) Core(TM) i7-8550U"
                        return line.split(":", 1)[1].strip()
        except (FileNotFoundError, PermissionError, IOError):
            pass

    # Try macOS sysctl for CPU brand string
    if name == "posix":
        try:
            from subprocess import run
            result = run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, Exception):
            pass

    # Final fallback to platform.processor()
    try:
        cpu = processor() or "Unknown"
        return cpu if cpu else "Unknown"
    except Exception:
        return "Unknown"


def banner():
    print(f'''
   █████████                      ████  ████                                
  ███░░░░░███                    ░░███ ░░███                                 
 ░███    ░███  ████████   ██████  ░███  ░███  █████ ████  ██████  ████████  
 ░███████████ ░░███░░███ ███░░███ ░███  ░███ ░░███ ░███  ███░░███░░███░░███ 
 ░███░░░░░███  ░███ ░███░███ ░███ ░███  ░███  ░███ ░███ ░███ ░███ ░███ ░███ 
 ░███    ░███  ░███ ░███░███ ░███ ░███  ░███  ░███ ░███ ░███ ░███ ░███ ░███ 
 █████   █████ ░███████ ░░██████  █████ █████ ░░███████ ░░██████  ████ █████
░░░░░   ░░░░░  ░███░░░   ░░░░░░  ░░░░░ ░░░░░   ░░░░░███  ░░░░░░  ░░░░ ░░░░░ 
               ░███                            ███ ░███                      
               █████                          ░░██████                       
              ░░░░░                            ░░░░░░''')  #  https://patorjk.com/software/taag/#p=display&f=DOS+Rebel&t=Apollyon&x=none&v=4&h=4&w=80&we=false


def info_box():
    """Display an ASCII box with system information."""
    # Gather system information
    try:
        username = getuser()
    except Exception:
        username = "Unknown"

    hostname = node() if node() else "Unknown"

    os_name = system()
    os_version = version() if version() else ""
    os_release = release()
    
    # Build OS line
    if os_version:
        os_line = f"{os_name} {os_version}"
    elif os_release:
        os_line = f"{os_name} ({os_release})"
    else:
        os_line = os_name

    platform_detail = platform()
    
    # CPU information - use the friendly name function
    cpu_name = _get_cpu_name()

    try:
        cpu_cores = cpu_count() or "Unknown"
    except Exception:
        cpu_cores = "Unknown"

    # RAM information
    try:
        import psutil
        ram = psutil.virtual_memory()
        total_gb = ram.total / (1024 ** 3)
        available_gb = ram.available / (1024 ** 3)
        total_ram = f"{total_gb:.1f} GB"
        available_ram = f"{available_gb:.1f} GB"
    except ImportError:
        try:
            # Fallback for Windows
            global_mem_status = ctypes.create_string_buffer(24)
            if hasattr(ctypes, 'kernel32') and ctypes.windll.kernel32.GlobalMemoryStatusEx(global_mem_status):
                total_ram_raw = int.from_bytes(global_mem_status[8:16], byteorder='little')
                avail_ram_raw = int.from_bytes(global_mem_status[16:24], byteorder='little')
                total_gb = total_ram_raw / (1024 ** 3)
                available_gb = avail_ram_raw / (1024 ** 3)
                total_ram = f"{total_gb:.1f} GB"
                available_ram = f"{available_gb:.1f} GB"
            else:
                total_ram = "Unknown"
                available_ram = "N/A"
        except Exception:
            total_ram = "Unknown"
            available_ram = "N/A"

    # --- Dynamic box width calculation ---
    MIN_BOX_WIDTH = 50
    MAX_CONTENT_WIDTH = 60  # max chars for content before truncation

    def calc_content_width(label: str, value: str) -> int:
        """Calculate the needed width for a line: '  LABEL VALUE'."""
        return len(f"  {label} {value}")

    # Compute all line widths to find the maximum
    line_widths = [
        calc_content_width("User:", username),
        calc_content_width("Computer:", hostname),
        calc_content_width("OS:", os_line),
        calc_content_width("Platform:", platform_detail),
        calc_content_width("CPU:", cpu_name),
        calc_content_width("Cores:", str(cpu_cores)),
        calc_content_width("RAM:", total_ram),
        calc_content_width("Available:", available_ram),
    ]

    # The title "SYSTEM INFORMATION" also needs space (with borders: "| TITLE |")
    title_needed = len("| SYSTEM INFORMATION |")
    line_widths.append(title_needed)

    max_needed = max(line_widths) if line_widths else MIN_BOX_WIDTH
    box_width = min(max(MIN_BOX_WIDTH, max_needed), MAX_CONTENT_WIDTH + 4)

    # Helper to truncate long values
    def truncate_value(label: str, value: str, total_width: int) -> str:
        """Truncate value so the full line fits within total_width."""
        needed = len(f"  {label} ")
        max_val_len = total_width - needed - 1  # -1 for trailing space before |
        if len(value) > max_val_len:
            return value[:max_val_len - 3] + "..."
        return value

    # Build the box
    lines = []

    # Top border
    lines.append("+" + "=" * box_width + "+")

    # Title row
    title = "SYSTEM INFORMATION"
    padding = (box_width - len(title)) // 2
    lines.append("|" + " " * padding + title + " " * (box_width - len(title) - padding) + "|")

    # Separator
    lines.append("+" + "-" * box_width + "+")

    # User section
    user_val = truncate_value("User:", username, box_width)
    user_padding = box_width - 3 - len("User:") - len(user_val)
    lines.append(f"|  User: {user_val}" + " " * max(0, user_padding) + "|")

    comp_val = truncate_value("Computer:", hostname, box_width)
    comp_padding = box_width - 3 - len("Computer:") - len(comp_val)
    lines.append(f"|  Computer: {comp_val}" + " " * max(0, comp_padding) + "|")

    # Separator
    lines.append("+" + "-" * box_width + "+")

    # OS section
    os_v = truncate_value("OS:", os_line, box_width)
    os_pad = box_width - 3 - len("OS:") - len(os_v)
    lines.append(f"|  OS: {os_v}" + " " * max(0, os_pad) + "|")

    plat_val = truncate_value("Platform:", platform_detail, box_width)
    plat_pad = box_width - 3 - len("Platform:") - len(plat_val)
    lines.append(f"|  Platform: {plat_val}" + " " * max(0, plat_pad) + "|")

    # Separator
    lines.append("+" + "-" * box_width + "+")

    # PC Specs section
    cpu_v = truncate_value("CPU:", cpu_name, box_width)
    cpu_pad = box_width - 3 - len("CPU:") - len(cpu_v)
    lines.append(f"|  CPU: {cpu_v}" + " " * max(0, cpu_pad) + "|")

    cores_val = str(cpu_cores)
    cores_pad = box_width - 3 - len("Cores:") - len(cores_val)
    lines.append(f"|  Cores: {cores_val}" + " " * max(0, cores_pad) + "|")

    ram_total_val = truncate_value("RAM:", total_ram, box_width)
    ram_total_pad = box_width - 3 - len("RAM:") - len(ram_total_val)
    lines.append(f"|  RAM: {ram_total_val}" + " " * max(0, ram_total_pad) + "|")

    ram_avail_val = truncate_value("Available:", available_ram, box_width)
    ram_avail_pad = box_width - 3 - len("Available:") - len(ram_avail_val)
    lines.append(f"|  Available: {ram_avail_val}" + " " * max(0, ram_avail_pad) + "|")

    # Bottom border
    lines.append("+" + "=" * box_width + "+")

    print("\n" + "\n".join(lines) + "\n")