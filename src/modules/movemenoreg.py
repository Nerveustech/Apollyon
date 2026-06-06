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

from os.path import (
    expandvars,
    expanduser,
    isdir,
    join,
    exists,
    isfile,
    dirname
)

from os import environ, remove, listdir
from hashlib import sha256
from re import match
from shutil import rmtree, move
from win32com.client import Dispatch
from win32.win32file import GetDriveType, DRIVE_REMOVABLE
from winreg import OpenKey, HKEY_CURRENT_USER, QueryValueEx
from modules.base import BaseModule, ModuleInfo, ModuleResult
from modules.core.process import kill_process, check_process_running


class MoveMenoregScanner(BaseModule):
    """Module for disinfecting movemenoreg malware from USB drives and Windows systems.

    This module scans for and removes indicators of compromise related to the
    movemenoreg family of malware, which uses a VBS-based persistence mechanism
    that creates malicious LNK files, helper.vbs, installer.vbs, and a
    WindowsServices folder containing movemenoreg.vbs.

    The malware operates by:
    1. Creating %APPDATA%\\WindowsServices\\movemenoreg.vbs (main payload)
    2. Dropping helper.vbs in the current directory
    3. Creating a startup LNK (helper.lnk) that runs wscript.exe with
       the argument /C .\\WindowsServices\\movemenoreg.vbs
    4. Backing up original files to a _ folder
    """

    MODULE_INFO = ModuleInfo(
        name="movemenoreg_scanner",
        description="Disinfects movemenoreg malware from USB drives and Windows systems",
        category="disinfection",
        version="1.0.0",
        author="Andrea Michael Maria Molino",
        tags=[
            "malware",
            "disinfection",
            "persistence",
            "movemenoreg",
            "vbs",
            "crypto-miner"
        ],
        platform="Windows",
        supported_targets=["system", "usb"],
    )

    # Malware indicators (ported from movemenoreg.h)
    HASH = {
        'helper.vbs': '102c7ef978fba6cd5e8c9269d80b5b7aad93e8b1abf91179667cac2aba123bb1',
        'installer.vbs': 'ca50a037690ee4deb6a18727cb4799a550cf57f3e7ce43562b6d422a85f30fcf',
        'movemenoreg.vbs': '4ecfe5da31ba8f780bbe6a959441e9120c7c8d96d4b9ee557934e8d97c01655a'
    }

    LNK_ARGUMENT = r"/C .\\WindowsServices\\movemenoreg.vbs"
    VBS_HELPER = "helper.vbs"
    STARTUP_LNK = "helper.lnk"
    VBS_INSTALLER = "installer.vbs"
    VBS_MAIN = "movemenoreg.vbs"
    EXE_MINER = "WindowsServices.exe"
    FOLDER_NAME = "WindowsServices"
    PROCESS_NAME = "wscript.exe"

    def analyze(self, target: str, **kwargs) -> ModuleResult:
        """Perform a read-only analysis of a target for MoveMenoreg threats.

        Uses ``_is_usb_mode`` to determine whether *target* is a removable drive.
        For USB targets the method scans for malicious LNK files, malware folders,
        and helper scripts without removing anything.  For system targets it checks
        the AppData folder and startup directory for indicators of compromise.

        Args:
            target: File path, directory, or drive letter to analyze.
            **kwargs: Additional parameters (e.g., ``deep_scan=True``).

        Returns:
            ModuleResult with analysis findings data (no modifications made).
        """
        deep_scan = kwargs.get("deep_scan", True)

        if target == "":
            return self._analyze_system(deep_scan=deep_scan)
        elif self._is_usb_mode(target):
            return self._analyze_usb(target, deep_scan=deep_scan)
            

    def _analyze_usb(self, target: str, deep_scan: bool = True) -> ModuleResult:
        """Read-only USB analysis — collect findings without removing anything."""
        findings = []
        expanded_target = expandvars(expanduser(target))

        if not isdir(expanded_target):
            return ModuleResult(
                success=False,
                data={"target": target, "error": f"Target path does not exist: {expanded_target}"},
            )

        # Scan for malicious LNK files
        lnk_findings = self._check_lnk_files(expanded_target, deep_scan)
        findings.extend(lnk_findings.get("findings", []))

        # Check for malware folder
        malware_folder_path = join(expanded_target, self.FOLDER_NAME)
        if exists(malware_folder_path):
            findings.append({
                "type": "malware_folder",
                "path": malware_folder_path,
                "severity": "high",
                "description": f"Malware folder detected: {malware_folder_path}",
            })

        # Check for helper scripts and verify their hashes
        for script in (self.VBS_HELPER, self.VBS_MAIN, self.EXE_MINER, self.VBS_INSTALLER):
            script_path = join(expanded_target, script)
            if isfile(script_path):
                hash_result = {}
                if script in self.HASH:
                    hash_result = self._check_file_hash(script_path, script)

                if hash_result.get("match"):
                    findings.append({
                        "type": "malicious_file",
                        "path": script_path,
                        "severity": "critical",
                        "description": f"Malicious file detected: {script}",
                        "hash_match": True,
                        "calculated_hash": hash_result.get("calculated_hash"),
                        "expected_hash": hash_result.get("expected_hash"),
                    })
                else:
                    findings.append({
                        "type": "suspicious_file",
                        "path": script_path,
                        "severity": "medium",
                        "description": f"Suspicious file with matching name but different hash: {script}",
                        "hash_match": False,
                        "calculated_hash": hash_result.get("calculated_hash"),
                        "expected_hash": hash_result.get("expected_hash"),
                    })

        # Check for backup folder (indicates previous infection)
        backup_folder = join(expanded_target, "_")
        if exists(backup_folder):
            findings.append({
                "type": "backup_folder",
                "path": backup_folder,
                "severity": "medium",
                "description": f"Backup folder detected (possible previous infection): {backup_folder}",
            })

        return ModuleResult(
            success=True,
            data={
                "target": target,
                "mode": "usb",
                "findings": findings,
                "actions": [],
                "total_threats_found": len(findings),
                "analysis_type": "read_only",
            },
        )

    def _analyze_system(self, deep_scan: bool = True) -> ModuleResult:
        """Read-only system analysis — collect findings without removing anything."""
        findings = []

        # Check wscript.exe process (informational only)
        if check_process_running(self.PROCESS_NAME, [self.VBS_HELPER, self.VBS_INSTALLER, self.VBS_MAIN]):
            findings.append({
                "type": "process_running",
                "process": self.PROCESS_NAME,
                "severity": "medium",
                "description": f"Process {self.PROCESS_NAME} is running (may indicate active malware)",
            })

        # Check AppData malware folder
        try:
            with OpenKey(HKEY_CURRENT_USER, r"Environment") as key:
                roaming_appdata = QueryValueEx(key, "APPDATA")[0]
        except (FileNotFoundError, OSError):
            roaming_appdata = expandvars(r"%APPDATA%")

        malware_folder_path = join(roaming_appdata, self.FOLDER_NAME)
        if exists(malware_folder_path):
            findings.append({
                "type": "malware_folder",
                "path": malware_folder_path,
                "severity": "high",
                "description": f"Malware folder detected in AppData: {malware_folder_path}",
            })
            # Check contents of the folder and verify hashes
            try:
                for entry in listdir(malware_folder_path):
                    entry_path = join(malware_folder_path, entry)
                    if isfile(entry_path):
                        hash_result = {}
                        if entry in self.HASH:
                            hash_result = self._check_file_hash(entry_path, entry)

                        if hash_result.get("match"):
                            findings.append({
                                "type": "malicious_file",
                                "path": entry_path,
                                "severity": "critical",
                                "description": f"Malicious file in AppData folder: {entry}",
                                "hash_match": True,
                                "calculated_hash": hash_result.get("calculated_hash"),
                                "expected_hash": hash_result.get("expected_hash"),
                            })
                        else:
                            findings.append({
                                "type": "suspicious_file",
                                "path": entry_path,
                                "severity": "medium",
                                "description": f"Suspicious file in AppData folder with different hash: {entry}",
                                "hash_match": False,
                                "calculated_hash": hash_result.get("calculated_hash"),
                                "expected_hash": hash_result.get("expected_hash"),
                            })
            except (PermissionError, OSError):
                pass

        # Check startup LNK
        try:
            shell = Dispatch("Shell.Application")
            startup_path = shell.NameSpace(shell.FOLDERID_Startup).Self.Path
        except (AttributeError, Exception):
            startup_path = join(environ.get("PUBLIC", ""), "Start Menu", "Programs", "Startup")

        startup_lnk_path = join(startup_path, self.STARTUP_LNK)
        if exists(startup_lnk_path):
            findings.append({
                "type": "startup_lnk",
                "path": startup_lnk_path,
                "severity": "high",
                "description": f"Malicious startup LNK detected: {startup_lnk_path}",
            })

        return ModuleResult(
            success=True,
            data={
                "target": "system",
                "mode": "system",
                "findings": findings,
                "actions": [],
                "total_threats_found": len(findings),
                "analysis_type": "read_only",
            },
        )

    def run(self, target: str, **kwargs) -> ModuleResult:
        """Execute the movemenoreg disinfection against the given target.

        Args:
            target: File path or directory to disinfect (for USB mode), ignored for PC mode.
            **kwargs:
                - mode: str - Operation mode: 'auto', 'usb', or 'pc' (default 'auto').
                - deep_scan: bool - Whether to perform deep LNK analysis (default True).

        Returns:
            ModuleResult with findings and actions data.
        """
        mode = kwargs.get("mode", "auto")
        deep_scan = kwargs.get("deep_scan", True)

        if mode == "usb" or (mode == "auto" and self._is_usb_mode(target)):
            return self.disinfect_usb(target, **kwargs)
        else:
            return self.disinfect_system(target, **kwargs)

    def disinfect_usb(self, target: str, **kwargs) -> ModuleResult:
        """Disinfect a USB drive from MoveMenoreg malware.

        Scans the target directory for malicious LNK files, removes the malware
        folder if present, and restores original files from the _ backup folder.

        Args:
            target: Path to the USB drive or directory to disinfect.
            **kwargs:
                - deep_scan: bool - Whether to perform deep LNK analysis (default True).

        Returns:
            ModuleResult with findings and actions data.
        """
        deep_scan = kwargs.get("deep_scan", True)
        findings = []
        actions_taken = []
        restored_files = []

        expanded_target = expandvars(expanduser(target))

        if not isdir(expanded_target):
            return ModuleResult(
                success=False,
                data={"target": target, "error": f"Target path does not exist: {expanded_target}"},
            )

        # Step 1: Scan and remove malicious LNK files
        lnk_findings = self._check_lnk_files(expanded_target, deep_scan)
        findings.extend(lnk_findings.get("findings", []))
        actions_taken.extend(lnk_findings.get("actions", []))

        # Step 2: Verify and remove malware folder if present
        malware_folder_path = join(expanded_target, self.FOLDER_NAME)
        if exists(malware_folder_path):
            findings.append({
                "type": "malware_folder",
                "path": malware_folder_path,
                "severity": "high",
                "description": f"Malware folder detected: {malware_folder_path}",
            })

            # Verify hashes of files in the malware folder before removal
            try:
                for entry in listdir(malware_folder_path):
                    entry_path = join(malware_folder_path, entry)
                    if isfile(entry_path) and entry in self.HASH:
                        hash_result = self._check_file_hash(entry_path, entry)
                        findings.append({
                            "type": "malicious_file",
                            "path": entry_path,
                            "severity": "critical",
                            "description": f"Malware file confirmed by hash on USB: {entry}",
                            "hash_match": hash_result.get("match"),
                            "calculated_hash": hash_result.get("calculated_hash"),
                            "expected_hash": hash_result.get("expected_hash"),
                        })
            except (PermissionError, OSError):
                pass

            try:
                rmtree(malware_folder_path)
                actions_taken.append({
                    "action": "folder_removed",
                    "path": malware_folder_path,
                    "status": "success",
                })
            except (PermissionError, OSError) as e:
                findings.append({
                    "type": "removal_failed",
                    "path": malware_folder_path,
                    "severity": "critical",
                    "description": f"Malware folder could not be removed: {e}",
                })

        # Step 3: Restore original files from _ backup folder
        restore_result = self._restore_original_files(expanded_target)
        findings.extend(restore_result.get("findings", []))
        restored_files.extend(restore_result.get("restored_files", []))
        actions_taken.extend(restore_result.get("actions", []))

        return ModuleResult(
            success=True,
            data={
                "target": target,
                "mode": "usb",
                "findings": findings,
                "actions": actions_taken,
                "restored_files": restored_files,
                "total_threats_found": len(findings),
            },
        )

    def disinfect_system(self, target: str = "", **kwargs) -> ModuleResult:
        """Disinfect a Windows PC from MoveMenoreg malware.

        Kills the wscript.exe process, removes the malware folder from AppData,
        and removes the startup LNK file.

        Args:
            target: Ignored for PC mode (kept for API compatibility).
            **kwargs: Additional parameters (unused in PC mode).

        Returns:
            ModuleResult with findings and actions data.
        """
        findings = []
        actions_taken = []

        # Step 1: Kill wscript.exe process
        kill_result = kill_process(self.PROCESS_NAME, [self.VBS_HELPER, self.VBS_INSTALLER, self.VBS_MAIN])
        if kill_result == 1:
            findings.append({
                "type": "process_not_running",
                "severity": "info",
                "description": f"Process {self.PROCESS_NAME} is not running.",
            })
        elif kill_result == 2:
            findings.append({
                "type": "process_kill_failed",
                "path": self.PROCESS_NAME,
                "severity": "critical",
                "description": f"Could not kill process {self.PROCESS_NAME}.",
            })
        elif kill_result == 3:
            actions_taken.append({
                "action": "process_killed",
                "process": self.PROCESS_NAME,
                "status": "success",
            })

        # Step 2: Remove malware folder from AppData
        
        try:
            with OpenKey(
                HKEY_CURRENT_USER,
                r"Environment",
            ) as key:
                roaming_appdata = QueryValueEx(key, "APPDATA")[0]
        except (FileNotFoundError, OSError):
            roaming_appdata = expandvars(r"%APPDATA%")

        malware_folder_path = join(roaming_appdata, self.FOLDER_NAME)

        if exists(malware_folder_path):
            findings.append({
                "type": "malware_folder",
                "path": malware_folder_path,
                "severity": "high",
                "description": f"Malware folder detected in AppData: {malware_folder_path}",
            })

            # Verify hashes of files in the malware folder before removal
            try:
                for entry in listdir(malware_folder_path):
                    entry_path = join(malware_folder_path, entry)
                    if isfile(entry_path) and entry in self.HASH:
                        hash_result = self._check_file_hash(entry_path, entry)
                        findings.append({
                            "type": "malicious_file",
                            "path": entry_path,
                            "severity": "critical",
                            "description": f"Malware file confirmed by hash in AppData: {entry}",
                            "hash_match": hash_result.get("match"),
                            "calculated_hash": hash_result.get("calculated_hash"),
                            "expected_hash": hash_result.get("expected_hash"),
                        })
            except (PermissionError, OSError):
                pass

            try:
                rmtree(malware_folder_path)
                actions_taken.append({
                    "action": "folder_removed",
                    "path": malware_folder_path,
                    "status": "success",
                })
            except (PermissionError, OSError) as e:
                findings.append({
                    "type": "removal_failed",
                    "path": malware_folder_path,
                    "severity": "critical",
                    "description": f"Malware folder could not be removed: {e}",
                })

        # Step 3: Remove startup LNK
        try:
            shell = Dispatch("Shell.Application")
            startup_path = shell.NameSpace(shell.FOLDERID_Startup).Self.Path
        except (AttributeError, Exception):
            startup_path = join(
                environ.get("PUBLIC", ""), "Start Menu", "Programs", "Startup"
            )

        startup_lnk_path = join(startup_path, self.STARTUP_LNK)

        if exists(startup_lnk_path):
            findings.append({
                "type": "startup_lnk",
                "path": startup_lnk_path,
                "severity": "high",
                "description": f"Malicious startup LNK detected: {startup_lnk_path}",
            })

            try:
                remove(startup_lnk_path)
                actions_taken.append({
                    "action": "startup_lnk_removed",
                    "path": startup_lnk_path,
                    "status": "success",
                })
            except (PermissionError, OSError) as e:
                findings.append({
                    "type": "removal_failed",
                    "path": startup_lnk_path,
                    "severity": "critical",
                    "description": f"Startup LNK could not be removed: {e}",
                })

        return ModuleResult(
            success=True,
            data={
                "target": target or "system",
                "mode": "pc",
                "findings": findings,
                "actions": actions_taken,
                "total_threats_found": len(findings),
            },
        )

    def _check_lnk_files(self, directory: str, deep_scan: bool = True) -> dict:
        """Scan a directory for malicious LNK files.

        Uses Windows ShellLink COM objects to resolve .lnk file targets and checks
        if they match the movemenoreg malware signature.

        Args:
            directory: Path to scan for LNK files.
            deep_scan: If True, perform deep analysis on all .lnk files.

        Returns:
            Dictionary with 'findings' list and 'actions' list.
        """
        findings = []
        actions = []
        shell = Dispatch("WScript.Shell")

        try:
            entries = listdir(directory)
        except (PermissionError, OSError):
            return {"findings": [], "actions": []}

        for entry in entries:
            if entry in (".", ".."):
                continue

            full_path = join(directory, entry)


            if isfile(full_path) and entry.lower().endswith(".lnk"):
                try:
                    lnk = shell.CreateShortcut(full_path)
                    target_args = lnk.Arguments if lnk.Arguments else ""
                    target_path = lnk.TargetPath if hasattr(lnk, 'TargetPath') else ""

                    # Check if the LNK argument matches the malware signature
                    if target_args == self.LNK_ARGUMENT or (
                        deep_scan and
                        self.LNK_ARGUMENT.replace("\\\\", "\\") in target_args
                    ):
                        findings.append({
                            "type": "malicious_lnk",
                            "path": full_path,
                            "severity": "critical",
                            "description": f"Malicious LNK detected: {entry}",
                            "arguments": target_args,
                            "target": target_path,
                        })

                        # Delete the malicious LNK file
                        try:
                            remove(full_path)
                            actions.append({
                                "action": "lnk_removed",
                                "path": full_path,
                                "status": "success",
                            })
                        except (PermissionError, OSError) as e:
                            findings.append({
                                "type": "removal_failed",
                                "path": full_path,
                                "severity": "high",
                                "description": f"Could not remove LNK file: {e}",
                            })
                except Exception:
                    # Skip files that can't be opened as shortcuts
                    continue

        return {"findings": findings, "actions": actions}

    def _restore_original_files(self, directory: str) -> dict:
        """Restore original files from the _ backup folder.

        Moves all files and folders from the _ subdirectory back to their
        original locations in the target directory.

        Args:
            directory: Path containing the _ backup folder.

        Returns:
            Dictionary with 'findings', 'restored_files' list, and 'actions' list.
        """
        findings = []
        restored_files = []
        actions = []
        backup_folder = join(directory, "_")

        if not exists(backup_folder):
            return {
                "findings": [{"type": "no_backup", "description": "No backup folder found."}],
                "restored_files": [],
                "actions": [],
            }

        try:
            entries = listdir(backup_folder)
        except (PermissionError, OSError):
            return {"findings": [], "restored_files": [], "actions": []}

        for entry in entries:
            if entry in (".", ".."):
                continue

            source_path = join(backup_folder, entry)
            dest_path = join(directory, entry)

            try:
                move(source_path, dest_path)
                restored_files.append(entry)
                actions.append({
                    "action": "file_restored",
                    "source": source_path,
                    "destination": dest_path,
                    "status": "success",
                })
            except (PermissionError, OSError) as e:
                findings.append({
                    "type": "restore_failed",
                    "path": source_path,
                    "severity": "high",
                    "description": f"Could not restore file: {e}",
                })

        # Remove the backup folder after restoration
        try:
            rmtree(backup_folder)
            actions.append({
                "action": "backup_folder_removed",
                "path": backup_folder,
                "status": "success",
            })
        except (PermissionError, OSError) as e:
            findings.append({
                "type": "removal_failed",
                "path": backup_folder,
                "severity": "medium",
                "description": f"Could not remove backup folder: {e}",
            })

        return {
            "findings": findings,
            "restored_files": restored_files,
            "actions": actions,
        }


    def _is_usb_mode(self, target: str) -> bool:
        """Determine if the target is likely a USB drive.

        Checks if the target path corresponds to a removable drive.

        Args:
            target: Path to check.

        Returns:
            True if the target appears to be a USB/removable drive.
        """
        try:
            shell = Dispatch("Shell.Application")
            namespace = shell.NameSpace(dirname(target) + "\\")

            if namespace is None:
                return False

            # Check drive type via win32 API
            drive = dirname(target).rstrip("\\")
            drive_type = GetDriveType(drive)
            if drive_type == DRIVE_REMOVABLE:
                return True
            else:
                return False

        except Exception:
            pass

        # Fallback: check if the path is a single-letter drive root
        return bool(match(r'^[A-Z]:\\$', target))

    def _check_file_hash(self, file_path: str, expected_key: str) -> dict:
        """Verify a file's SHA-256 hash against the expected malware hash.

        Args:
            file_path: Path to the file to verify.
            expected_key: Key name in ``self.HASH`` dictionary (e.g. ``'helper.vbs'``).

        Returns:
            Dictionary with match status, calculated hash, and expected hash.
        """
        if not isfile(file_path):
            return {"match": False, "calculated_hash": None, "expected_hash": None}

        try:
            with open(file_path, "rb") as f:
                calculated = sha256(f.read()).hexdigest()

            expected = self.HASH.get(expected_key)
            return {
                "match": calculated == expected,
                "calculated_hash": calculated,
                "expected_hash": expected,
            }
        except (OSError, IOError):
            return {"match": False, "calculated_hash": None, "expected_hash": None}

