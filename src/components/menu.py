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


from utils import clear_screen, validate_and_sanitize_path
from components.ui import banner
from modules import ModuleRegistry, ModuleStatus, BaseModule

# AI decision support (optional, loaded lazily)
_ai_engine = None


def get_ai_engine():
    """Get or create the AI decision engine instance (lazy-loaded)."""
    global _ai_engine
    if _ai_engine is None:
        try:
            from components.llm import get_ai_engine as _get_ai_engine
            _ai_engine = _get_ai_engine()
        except ImportError:
            pass
    return _ai_engine


# Global registry instance (lazy-loaded on first use)
_registry = None


def get_registry() -> ModuleRegistry:
    """Get or create the global module registry instance."""
    global _registry
    if _registry is None:
        _registry = ModuleRegistry()
    return _registry


def ai_status_indicator():
    """Print an AI availability indicator if the engine is configured."""
    engine = get_ai_engine()
    if engine and hasattr(engine, "is_available") and engine.is_available:
        print("[AI] Active — decision support enabled")


def display_ai_response(title: str, response) -> None:
    """Display an AI response in a formatted box.

    Args:
        title: The section title (e.g., "Threat Analysis", "Module Recommendation").
        response: An AIResponse object with content and metadata.
    """
    print()
    separator()
    center = f"  {title}"
    print("|" + center + " " * (39 - len(center)) + "|")
    separator()

    if not response or not response.success:
        print(f"|  ⚠ AI unavailable: {response.error if response else 'Not configured'}")
    elif response.content:
        # Wrap long content for terminal width
        content = response.content.strip()
        lines = content.split("\n")
        for line in lines:
            # Truncate very long lines to fit the box
            display_line = line if len(line) + 2 <= 38 else line[:35] + "..."
            print(f"|  {display_line}")
    else:
        print("|  No AI response generated.")

    separator()
    print()


def display_menu(title: str, options: list[dict]):
    """Display a formatted menu with a title and options.

    Args:
        title: The menu title text.
        options: A list of dicts with keys 'key', 'label', and optionally 'action'.
                 - key: Single character identifier (e.g., '1', '0')
                 - label: Display text for the option
                 - action: Optional callable to execute when selected
    """
    print()
    # Title as plain text, centered
    print(f"  {title}")
    print("─" * 42)

    for opt in options:
        label = opt["label"]
        key = opt.get("key", "")
        line = f"  [{key}] {label}"
        # Truncate if too long
        if len(line) > 42:
            line = line[:39] + "..."
        print(line)

    print()


def separator():
    """Print a separator row for menus."""
    print("|" + "-" * 40 + "|")


def get_choice(prompt: str = "Enter your choice") -> str:
    """Get and validate user input as a single choice.

    Args:
        prompt: The prompt text to display.

    Returns:
        The user's selected key string.
    """
    while True:
        try:
            choice = input(f"\n{prompt}: ").strip()
            if choice:
                return choice
        except EOFError:
            return ""
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return "exit"


def analyze_submenu():
    """Display the Analyze sub-menu and return the user's selection.

    Returns:
        A dict with 'action' key describing the selected scan target, or None if back was chosen.
    """
    registry = get_registry()
    options = [
        {
            "key": "1",
            "label": "Entire Computer",
            "action": "entire_computer"
        },
        {
            "key": "2",
            "label": "USB / SD Card",
            "action": "usb_sdcard"
        },
        {
            "key": "3",
            "label": f"Analyze - Run Modules ({len(registry)} modules)",
            "action": "analyze_modules"
        },
        {
            "key": "4",
            "label": f"Disinfect - Run Modules ({len(registry)} modules)",
            "action": "run_modules"
        },
        {
            "key": "0",
            "label": "Back",
            "action": "back"
        },
    ]

    while True:
        display_menu("ANALYZE", options)
        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                return opt
        # Invalid input: re-prompt instead of returning None
        clear_screen()


def modules_list_menu(mode: str = "disinfect"):
    """Display a list of all registered modules with their information.

    The user can select a module to run, which will then prompt for target selection
    (System or USB) and execute the appropriate method.

    Args:
        mode: Either 'analyze' (calls analyze()) or 'disinfect' (calls disinfect methods).

    Returns:
        A dict with 'module' (BaseModule), 'target_type' ('system' or 'usb'),
        'path', and 'mode', or None if back was chosen.
    """
    registry = get_registry()
    all_modules = registry.modules

    if not all_modules:
        print("\n  No modules found.\n")
        input("Press Enter to continue...")
        return {"action": "back"}

    # Build the list of module options with info
    mod_names = sorted(all_modules.keys())
    options = []
    for i, name in enumerate(mod_names, 1):
        mod = all_modules[name]
        info = mod.MODULE_INFO
        targets_str = ", ".join(info.supported_targets) if info.supported_targets else "none"
        label = f"{name} | {info.category} | [{targets_str}] | {mod.status.value}"
        options.append({
            "key": str(i),
            "label": label,
            "action": "select_module",
            "module_name": name,
        })

    options.append({"key": "0", "label": "Back", "action": "back"})

    while True:
        print()
        mode_prefix = "ANALYZE" if mode == "analyze" else "DISINFECT"
        title = f"{mode_prefix} - ALL MODULES ({len(mod_names)})"
        print(f"  {title}")
        print("─" * 42)

        # Column header
        print(f"  {'':<3} {'Name':<25} {'Category':<10} {'Targets':<12} {'Status':<12}")
        print("   ──── ───────────────────────── ────────── ──────────── ────────────")

        for opt in options:
            if opt["action"] == "select_module":
                mod = all_modules[opt["module_name"]]
                info = mod.MODULE_INFO
                targets_str = ", ".join(info.supported_targets) if info.supported_targets else "none"
                # Truncate name if too long
                display_name = opt["module_name"][:25] if len(opt["module_name"]) > 25 else opt["module_name"]
                print(f"   [{opt['key']}] {display_name:<25} {info.category[:10]:<10} {targets_str[:12]:<12} {mod.status.value[:12]:<12}")
            else:
                label = opt["label"][:38] if len(opt["label"]) > 38 else opt["label"]
                print(f"   [{opt['key']}] {label}")

        print()

        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                if opt["action"] == "select_module":
                    # Show target selection for this module
                    return target_selection_menu(all_modules[opt["module_name"]], mode=mode)
                elif opt["action"] == "back":
                    return {"action": "back"}

        # Invalid input: re-prompt
        clear_screen()


def target_selection_menu(module: BaseModule, mode: str = "disinfect") -> dict | None:
    """Display target selection menu for a module.

    Based on the module's supported_targets, shows options for System and/or USB.
    After selecting a target, prompts for a path and executes the appropriate method.

    Args:
        module: The selected BaseModule instance.
        mode: Either 'analyze' (calls analyze()) or 'disinfect' (calls disinfect methods).

    Returns:
        A dict with 'module', 'target_type' ('system' or 'usb'), and 'path',
        or None if back was chosen.
    """
    info = module.MODULE_INFO
    supported = info.supported_targets if info.supported_targets else []

    options = []
    key_counter = 1

    # System option
    if "system" in supported:
        if mode == "analyze":
            method_label = f"{module.MODULE_INFO.name}.analyze()"
        else:
            method_label = f"{module.MODULE_INFO.name}.disinfect_system()"
        options.append({
            "key": str(key_counter),
            "label": f"System    - Run {method_label}",
            "action": "target_system",
            "target_type": "system",
        })
        key_counter += 1

    # USB option
    if "usb" in supported:
        if mode == "analyze":
            method_label = f"{module.MODULE_INFO.name}.analyze()"
        else:
            method_label = f"{module.MODULE_INFO.name}.disinfect_usb()"
        options.append({
            "key": str(key_counter),
            "label": f"USB       - Run {method_label}",
            "action": "target_usb",
            "target_type": "usb",
        })
        key_counter += 1

    options.append({"key": "0", "label": "Back", "action": "back"})

    if not options or len(options) == 1:
        # Only back option or no targets
        pass

    while True:
        print()
        mode_label = "ANALYZE" if mode == "analyze" else "DISINFECT"
        title = f"{mode_label} selection for module: {module.MODULE_INFO.name}"
        print(f"  {title}")
        print("─" * 42)

        for opt in options:
            label = opt["label"][:38] if len(opt["label"]) > 38 else opt["label"]
            print(f"  [{opt['key']}] {label}")

        print()

        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                if opt["action"] == "back":
                    return {"action": "back"}

                # Get the path for this target
                use_empty_for_system = (mode == "analyze" and opt["target_type"] == "system")
                path = _get_target_path(opt["target_type"], use_empty_for_system=use_empty_for_system)
                if path is None:
                    continue  # User cancelled path input

                return {
                    "module": module,
                    "module_name": module.MODULE_INFO.name,
                    "target_type": opt["target_type"],
                    "path": path,
                    "mode": mode,
                }

        clear_screen()


def _get_target_path(target_type: str, use_empty_for_system: bool = False) -> str | None:
    """Prompt the user for a target path based on target type.

    Args:
        target_type: Either 'system' or 'usb'.
        use_empty_for_system: If True and target is 'system', returns empty string
            without prompting (for system analysis mode).

    Returns:
        The validated path string, or None if the user cancelled.
        Returns empty string for system when use_empty_for_system is True.
    """
    if target_type == "system":
        if use_empty_for_system:
            return ""
        prompt = "Enter system target path (e.g., C:\\) [default: C:\\]: "
        default_path = "C:\\"
    else:
        prompt = "Enter USB/SD card path or drive letter (e.g., D:\\): "
        default_path = None

    while True:
        try:
            user_input = input(f"\n{prompt}").strip()
        except EOFError:
            return None
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return None

        # Use default path if empty and one exists
        if not user_input and default_path:
            return default_path

        if not user_input:
            print("Error: Path cannot be empty. Please try again.")
            continue

        sanitized = validate_and_sanitize_path(user_input)
        if sanitized:
            return sanitized

        print(f"Error: Path '{user_input}' does not exist. Please try again.")


def run_module_result_dialog(module: BaseModule, target_type: str, path: str) -> None:
    """Execute a module's disinfect method and display the result.

    Args:
        module: The BaseModule instance to execute.
        target_type: Either 'system' or 'usb'.
        path: The target path for execution.
    """
    print()
    separator()
    print(f"|  Running module: {module.MODULE_INFO.name}")
    print(f"|  Target type : {target_type.upper()}")
    print(f"|  Path        : {path}")
    separator()

    # Determine which method to call based on target type
    if target_type == "system":
        method_name = "disinfect_system"
        result = module.disinfect_system(path)
    elif target_type == "usb":
        method_name = "disinfect_usb"
        result = module.disinfect_usb(path)
    else:
        print(f"|  Error: Unknown target type '{target_type}'")
        input("\nPress Enter to continue...")
        return

    # Display results
    separator()
    status_icon = "[+]" if result.success else "[!]"
    print(f"|  {status_icon} Module: {module.MODULE_INFO.name}")
    print(f"|  Method : {method_name}")
    print(f"|  Status : {'Success' if result.success else 'Failed'}")

    if result.data and isinstance(result.data, dict):
        threats = result.data.get("total_threats_found", 0)
        print(f"|  Threats found: {threats}")

        actions = result.data.get("actions", [])
        if actions:
            print(f"|  Actions taken: {len(actions)}")
            for action in actions:
                action_type = action.get("action", "unknown")
                action_path = action.get("path", action.get("destination", ""))
                action_status = action.get("status", "")
                print(f"      - {action_type}: {action_path} [{action_status}]")

        restored = result.data.get("restored_files", [])
        if restored:
            print(f"|  Restored files: {', '.join(restored)}")

    if result.error:
        print(f"|  Error  : {result.error}")

    separator()
    print()


def analyze_module_result_dialog(module: BaseModule, target_type: str, path: str) -> None:
    """Execute a module's analyze method and display the result.

    Args:
        module: The BaseModule instance to execute.
        target_type: Either 'system' or 'usb'.
        path: The target path for analysis (empty string for system analysis).
    """
    print()
    separator()
    print(f"|  Analyzing module: {module.MODULE_INFO.name}")
    print(f"|  Target type : {target_type.upper()}")
    print(f"|  Path        : {path if path else '(system)' }")
    separator()

    # Call the analyze method with the path
    result = module.analyze(path)

    # Display results
    separator()
    status_icon = "[+]" if result.success else "[!]"
    print(f"|  {status_icon} Module: {module.MODULE_INFO.name}")
    print(f"|  Method : analyze")
    print(f"|  Status : {'Success' if result.success else 'Failed'}")

    if result.data and isinstance(result.data, dict):
        threats = result.data.get("total_threats_found", 0)
        print(f"|  Threats found: {threats}")

        scanned = result.data.get("total_files_scanned", 0)
        print(f"|  Files scanned: {scanned}")

        actions = result.data.get("actions", [])
        if actions:
            print(f"|  Findings: {len(actions)}")
            for action in actions:
                finding_type = action.get("action", "unknown")
                finding_path = action.get("path", action.get("destination", ""))
                finding_status = action.get("status", "")
                print(f"      - {finding_type}: {finding_path} [{finding_status}]")

        restored = result.data.get("restored_files", [])
        if restored:
            print(f"|  Restored files: {', '.join(restored)}")

    if result.error:
        print(f"|  Error  : {result.error}")

    separator()
    print()


def modules_submenu():
    """Display the Modules sub-menu and return the user's selection.

    Returns:
        A dict with module info, or None if back was chosen.
    """
    registry = get_registry()

    # Build category options
    categories = registry.categories
    options = []

    for i, cat in enumerate(categories, 1):
        count = len(registry.get_by_category(cat))
        label = f"{cat} ({count} module{'s' if count != 1 else ''})"
        options.append({
            "key": str(i),
            "label": label,
            "action": "category",
            "category": cat,
        })

    # Add "View All Modules" option at the top
    options.insert(0, {
        "key": "0",  # Temporary key, will renumber below
        "label": f"View All Modules ({len(registry)} modules)",
        "action": "view_all",
    })

    # Renumber keys after inserting "View All" at position 0
    for i, opt in enumerate(options):
        if opt["key"] != "0" or opt["action"] == "view_all":
            opt["key"] = str(i)

    # Add "Run All" option
    if len(registry) > 0:
        options.append({
            "key": str(len(categories) + 1),
            "label": f"Run All ({len(registry)} modules)",
            "action": "run_all",
        })

    # Add status filter options
    options.extend([
        {
            "key": str(len(categories) + 2),
            "label": f"Ready Modules ({registry.summary().get(ModuleStatus.READY, 0)})",
            "action": "filter_ready",
        },
        {
            "key": str(len(categories) + 3),
            "label": f"Completed Modules ({registry.summary().get(ModuleStatus.COMPLETED, 0)})",
            "action": "filter_completed",
        },
    ])

    options.append({
        "key": str(len(options)),
        "label": "Back",
        "action": "back"
    })

    while True:
        display_menu("MODULES", options)
        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                return opt
        clear_screen()


def display_module_info(module: BaseModule):
    """Display detailed information about a module.

    Args:
        module: A BaseModule instance to display info for.
    """
    info = module.MODULE_INFO
    print()
    separator()
    print(f"|  Module: {info.name}")
    separator()
    print(f"|  Description: {info.description}")
    print(f"|  Category: {info.category}")
    print(f"|  Version: {info.version}")
    if info.author:
        print(f"|  Author: {info.author}")
    if info.tags:
        print(f"|  Tags: {', '.join(info.tags)}")
    separator()
    print(f"|  Status: {module.status.value}")
    if module.last_result:
        result = module.last_result
        print(f"|  Last Result: {'Success' if result.success else 'Failed'}")
        if result.error:
            print(f"|  Error: {result.error}")
        if result.execution_time > 0:
            print(f"|  Execution Time: {result.execution_time:.2f}s")
    separator()


def display_module_results(target: str, results: dict):
    """Display execution results for modules.

    Args:
        target: The scan target that was used.
        results: Dictionary of module name -> ModuleResult.
    """
    print()
    separator()
    center = f"  Results for: {target}"
    print("|" + center + " " * (40 - len(center)) + "|")
    separator()

    for name, result in results.items():
        status_icon = "[+]" if result.success else "[!]"
        print(f"|  {status_icon} {name}")
        if result.data:
            if isinstance(result.data, dict):
                threats = result.data.get("threats_found", 0)
                scanned = result.data.get("total_files_scanned", 0)
                print(f"|     Scanned: {scanned} files | Threats found: {threats}")
        if result.error:
            print(f"|     Error: {result.error}")

    separator()


def ai_main_menu():
    """Display the AI quick-access submenu from the main menu.

    Returns:
        A dict with action and optional data, or None if back was chosen.
    """
    engine = get_ai_engine()
    registry = get_registry()

    options = [
        {"key": "1", "label": "Analyze Current Threats (from last scan)", "action": "analyze_threats"},
        {"key": "2", "label": "Recommend Next Modules", "action": "recommend_modules"},
        {"key": "3", "label": "Suggest Disinfection Strategy", "action": "suggest_strategy"},
        {"key": "4", "label": "Summarize Full Scan Results", "action": "summarize_scan"},
        {"key": "5", "label": "Ask AI a Security Question", "action": "ask_question"},
        {"key": "6", "label": f"Explain Last Module Result ({registry.modules if registry else 'none'})", "action": "explain_result"},
        {"key": "0", "label": "Back", "action": "back"},
    ]

    while True:
        display_menu("AI DECISION SUPPORT", options)
        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                return opt
        clear_screen()


def main_menu():
    """Display the main menu and return the user's selection.

    Returns:
        A dict with 'action' key describing the selected top-level option, or None if exit was chosen.
    """
    registry = get_registry()
    options = [
        {
            "key": "1",
            "label": "Analyze",
            "action": "analyze"
        },
        {
            "key": "2",
            "label": f"Modules ({len(registry)} available)",
            "action": "modules"
        },
        {
            "key": "3",
            "label": "🤖 AI Decision Support",
            "action": "ai_support"
        },
        {
            "key": "0",
            "label": "Exit",
            "action": "exit"
        },
    ]

    while True:
        display_menu("MAIN MENU", options)
        choice = get_choice()

        for opt in options:
            if choice == opt["key"]:
                return opt
        # Invalid input: re-prompt instead of returning None
        clear_screen()


def run_menu_loop():
    """Main menu loop that handles navigation between menus.

    This function keeps the program running, presenting menus and
    dispatching actions until the user chooses to exit.
    """
    while True:
        clear_screen()  # Clear screen before showing each menu
        banner()  # Display the ASCII art banner
        # Main Menu
        selection = main_menu()
        if selection is None or selection["action"] == "exit":
            print("\nGoodbye!\n")
            break

        if selection["action"] == "analyze":
            # Analyze Sub-Menu
            analysis = analyze_submenu()
            if analysis is None or analysis["action"] == "back":
                continue  # Back to main menu
            if analysis["action"] == "usb_sdcard":
                while True:
                    user_path = input("\nEnter USB/SD card path or drive letter (e.g., D:\\): ").strip()
                    sanitized = validate_and_sanitize_path(user_path)
                    if sanitized:
                        break
                    print(f"Error: Path '{user_path}' does not exist. Please try again.")
                print(f"\n> Running analysis on: {analysis['label']} at {sanitized}")
                # TODO: Implement actual analysis logic here with the sanitized path
                input("\nPress Enter to return to the main menu...")
            elif analysis["action"] == "entire_computer":
                print(f"\n> Running analysis on: {analysis['label']}")
                # TODO: Implement actual analysis logic here
                input("\nPress Enter to return to the main menu...")
            elif analysis["action"] == "analyze_modules":
                # Analyze modules - user selects module, then chooses System or USB
                while True:
                    result = modules_list_menu(mode="analyze")
                    if result is None or result.get("action") == "back":
                        break
                    # Execute the selected module's analyze method
                    mod = result.get("module")
                    target_type = result.get("target_type")
                    path = result.get("path")
                    if mod and target_type and path is not None:
                        analyze_module_result_dialog(mod, target_type, path)
                        input("Press Enter to return to module list...")
            elif analysis["action"] == "run_modules":
                # Run modules submenu
                module_selection = modules_submenu()
                if module_selection is None or module_selection["action"] == "back":
                    continue

                # Get target path
                while True:
                    user_path = input("\nEnter scan target path (e.g., C:\\, D:\\): ").strip()
                    sanitized = validate_and_sanitize_path(user_path)
                    if sanitized:
                        break
                    print(f"Error: Path '{user_path}' does not exist. Please try again.")

                registry = get_registry()
                results = {}

                if module_selection["action"] == "run_all":
                    for name in registry:
                        print(f"\n> Running module: {name}...")
                        result = registry.run_module(name, sanitized)
                        results[name] = result
                elif module_selection["action"] in ("category", "filter_ready", "filter_completed"):
                    # Get filtered modules
                    if module_selection["action"] == "category":
                        mods = registry.get_by_category(module_selection["category"])
                    elif module_selection["action"] == "filter_ready":
                        mods = {n: m for n, m in registry.modules.items() if m.status == ModuleStatus.READY}
                    elif module_selection["action"] == "filter_completed":
                        mods = {n: m for n, m in registry.modules.items() if m.status == ModuleStatus.COMPLETED}

                    # Display available modules and let user select
                    mod_names = list(mods.keys())
                    mod_options = []
                    for i, name in enumerate(sorted(mod_names), 1):
                        mod = mods[name]
                        mod_options.append({
                            "key": str(i),
                            "label": f"{name} ({mod.status.value})",
                            "action": "run_single",
                            "module_name": name,
                        })
                    mod_options.append({"key": "0", "label": "Run Selected Modules", "action": "run_selected"})
                    mod_options.append({"key": "-1", "label": "Back", "action": "back"})

                    while True:
                        display_menu("SELECT MODULES", mod_options)
                        choice = get_choice()

                        if choice == "0":
                            # Run all displayed modules
                            for opt in mod_options:
                                if opt["action"] == "run_single" and opt.get("module_name"):
                                    print(f"\n> Running module: {opt['module_name']}...")
                                    result = registry.run_module(opt["module_name"], sanitized)
                                    results[opt["module_name"]] = result
                            break
                        elif choice == "-1":
                            continue
                        else:
                            for opt in mod_options:
                                if choice == opt["key"] and opt.get("action") == "run_single":
                                    print(f"\n> Running module: {opt['module_name']}...")
                                    result = registry.run_module(opt["module_name"], sanitized)
                                    results[opt["module_name"]] = result
                                    break

                display_module_results(sanitized, results)
                input("\nPress Enter to return to the main menu...")

        elif selection["action"] == "ai_support":
            # AI Decision Support Sub-Menu
            while True:
                clear_screen()
                ai_selection = ai_main_menu()
                if ai_selection is None or ai_selection["action"] == "back":
                    break

                engine = get_ai_engine()
                registry = get_registry()

                if not engine or (hasattr(engine, "is_available") and not engine.is_available):
                    print("\n  ⚠ AI engine not available. Please configure your API key in .env file.\n")
                    input("Press Enter to continue...")
                    continue

                action = ai_selection["action"]

                if action == "analyze_threats":
                    # Analyze threats from last scan results
                    print("\n  ⚠ Threat analysis: No previous scan data available.")
                    display_ai_response("Threat Analysis", None)
                    input("\nPress Enter to continue...")
                elif action == "recommend_modules":
                    # Recommend next modules based on detected threats
                    all_threats = []
                    all_modules = list(registry.modules.items())
                    mod_list = [{"name": n, "category": m.MODULE_INFO.category} for n, m in all_modules]
                    response = engine.recommend_modules(all_threats, mod_list)
                    display_ai_response("Module Recommendations", response)
                    input("\nPress Enter to continue...")
                elif action == "suggest_strategy":
                    # Suggest disinfection strategy
                    scan_summary = {
                        "total_threats": 0,
                        "files_affected": [],
                        "infection_types": [],
                        "threat_details": [],
                    }
                    response = engine.suggest_disinfection_strategy(scan_summary)
                    display_ai_response("Disinfection Strategy", response)
                    input("\nPress Enter to continue...")
                elif action == "summarize_scan":
                    # Summarize full scan results
                    full_results = {
                        "files_scanned": 0,
                        "total_threats": 0,
                        "modules_run": [],
                        "scan_duration": 0.0,
                        "module_results": {},
                    }
                    response = engine.summarize_scan(full_results)
                    display_ai_response("Scan Summary", response)
                    input("\nPress Enter to continue...")
                elif action == "ask_question":
                    question = get_choice("Ask your security question:")
                    if question and question.lower() != "exit":
                        response = engine.answer_question(question)
                        display_ai_response("Security Q&A", response)
                    input("\nPress Enter to continue...")
                elif action == "explain_result":
                    # Explain last module result
                    print("\n  ⚠ No previous module results available.")
                    display_ai_response("Module Explanation", None)
                    input("\nPress Enter to continue...")

        elif selection["action"] == "modules":
            # Modules submenu from main menu
            module_selection = modules_submenu()
            if module_selection is None or module_selection["action"] == "back":
                continue

            registry = get_registry()

            if module_selection["action"] == "view_all":
                # Show the full module list with run capability
                while True:
                    result = modules_list_menu()
                    if result is None or result.get("action") == "back":
                        break
                    # Execute the selected module
                    mod = result.get("module")
                    target_type = result.get("target_type")
                    path = result.get("path")
                    if mod and target_type and path:
                        run_module_result_dialog(mod, target_type, path)
                        input("Press Enter to return to module list...")
            elif module_selection["action"] == "category":
                mods = registry.get_by_category(module_selection["category"])
                for name, mod in sorted(mods.items()):
                    display_module_info(mod)
                    input("\nPress Enter to continue...")
            elif module_selection["action"] == "filter_ready":
                mods = {n: m for n, m in registry.modules.items() if m.status == ModuleStatus.READY}
                for name, mod in sorted(mods.items()):
                    display_module_info(mod)
                    input("\nPress Enter to continue...")
            elif module_selection["action"] == "filter_completed":
                mods = {n: m for n, m in registry.modules.items() if m.status == ModuleStatus.COMPLETED}
                for name, mod in sorted(mods.items()):
                    display_module_info(mod)
                    input("\nPress Enter to continue...")
