#
#  MIT License
#
#  Copyright (c) 2026 Andrea Michael M. Molino
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#

from psutil import (
    process_iter,
    NoSuchProcess,
    AccessDenied,
    ZombieProcess,
    Process
)

def check_process_running(proc_name: str, cmdline_args: list = None) -> bool:
    """Check if a process is running by name.

    Args:
        proc_name: Name of the process to check (e.g., 'wscript.exe').
        cmdline_args: Optional list of command-line arguments to match against
                      the process command line for more precise targeting.

    Returns:
        True if the process is found running, False otherwise.
    """
    proc_name_lower = proc_name.lower()

    for proc in process_iter(['name', 'cmdline']):
        try:
            # Skip processes with no name or None name
            if not proc.info['name']:
                continue

            # Check if process name matches (case-insensitive substring match)
            if proc_name_lower not in proc.info['name'].lower():
                continue

            # If cmdline_args specified, verify at least one arg is in the command line
            if cmdline_args:
                cmdline = proc.info['cmdline']
                if not cmdline or not any(
                    any(arg.lower() in str(cmd_line).lower() for cmd_line in cmdline)
                    for arg in cmdline_args
                ):
                    continue  # Skip, cmdline doesn't match

            return True  # Process found running

        except NoSuchProcess:
            continue
        except AccessDenied:
            continue
        except ZombieProcess:
            continue
        except Exception:
            continue

    return False  # Process not found


def kill_process(proc_name: str, cmdline_args: list = None) -> int:
    """Kill a running process by name.

    Args:
        proc_name: Name of the process to kill (e.g., 'wscript.exe').
        cmdline_args: Optional list of command-line arguments to match against
                      the process command line for more precise targeting.

    Returns:
        1 if process was not found/running.
        2 if process could not be killed.
        3 if process was successfully killed.
    """
    proc_name_lower = proc_name.lower()

    for proc in process_iter(['pid', 'name', 'cmdline']):
        try:
            # Skip processes with no name or None name
            if not proc.info['name']:
                continue

            # Check if process name matches (case-insensitive substring match)
            if proc_name_lower not in proc.info['name'].lower():
                continue

            pid = proc.info['pid']

            # If cmdline_args specified, verify at least one arg is in the command line
            if cmdline_args:
                cmdline = proc.info['cmdline']
                if not cmdline or not any(
                    any(arg.lower() in str(cmd_line).lower() for cmd_line in cmdline)
                    for arg in cmdline_args
                ):
                    continue  # Skip, cmdline doesn't match

            try:
                process = Process(pid)
                process.terminate()
                return 3  # Successfully killed
            except NoSuchProcess:
                continue
            except AccessDenied:
                return 2  # Could not kill (permission denied)
            except ZombieProcess:
                return 2  # Could not kill (process is a zombie)
            except Exception:
                return 2  # Could not kill (other error)

        except NoSuchProcess:
            continue
        except AccessDenied:
            continue
        except ZombieProcess:
            continue
        except Exception:
            continue

    return 1  # Process not found