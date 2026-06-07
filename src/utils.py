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

from sys import platform, stdout
from ctypes import windll
from os import path as os_path
from sys import platform
from subprocess import call


def set_title(title: str = "Apollyon") -> None:
    """Set the terminal/console title in a cross-platform manner.
    
    Supports Windows, Linux, and macOS by using platform-specific APIs:
    - Windows: Uses ctypes to call SetConsoleTitleW (Windows API)
    - Linux/macOS: Uses ANSI escape sequences (OSC 0 / OSC 2)
    
    Args:
        title: The title string to set for the terminal window.
    """
    if not title:
        return

    try:
        if platform == "win32":
            # Windows: use SetConsoleTitleW via ctypes
            try:
                windll.kernel32.SetConsoleTitleW(title)
            except (AttributeError, OSError):
                pass
        else:
            # Linux / macOS: use ANSI escape sequences
            try:
                # OSC 0 sets both icon name and window title
                stdout.write(f'\x1b]0;{title}\x07')
                stdout.flush()
            except Exception:
                pass

    except Exception:
        pass


def clear_screen() -> None:
    """Clear the terminal screen."""
    call("cls", shell=True) if platform == "win32" else call("clear", shell=True)


def validate_and_sanitize_path(user_input: str) -> str | None:
    """Validate and sanitize a file system path provided by the user.

    Handles common Windows input formats like drive letters (D, D:, E) and
    converts them into canonical absolute paths.

    Args:
        user_input: The raw string entered by the user (e.g., "D", "D:", "E:\\", "F:\\data").

    Returns:
        The sanitized, absolute path if valid (e.g., "D:\\"), or None if invalid/missing.
    """
    if not user_input:
        return None

    # Strip surrounding whitespace
    cleaned = user_input.strip()

    # Handle bare drive letter without colon (e.g., "D" -> "D:")
    if len(cleaned) == 1 and cleaned.isalpha():
        cleaned = cleaned + ":"

    # Normalize to absolute path
    normalized = os_path.abspath(cleaned)

    # Check existence
    if not os_path.exists(normalized):
        return None

    return normalized


# Keep the old name as an alias for backward compatibility if needed elsewhere.
validate_path = validate_and_sanitize_path