from os import path as os_path
from sys import platform
from subprocess import call


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