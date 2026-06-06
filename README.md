# Apollyon

<div align="center">

  <img src="https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">

</div>

**Apollyon** is a modular malware tracking and removal toolkit for Windows, Linux, MacOS, featuring AI-powered decision support. It provides intelligent detection and disinfection of threats from both the operating system and removable (USB) drives.

> *Named after the angel of destruction in biblical prophecy, Apollyon systematically eliminates malicious artifacts from your system.*

---

## Features

- **🔍 Modular Architecture** — Pluggable modules with a standardized interface for easy extension
- **🛡️ Dual-Mode Scanning** — Analyze and disinfect both the Windows system and USB/removable drives
- **⚖️ Two Operation Modes**:
  - **Analysis (Read-Only)** — Detect threats without making any modifications
  - **Disinfection** — Actively remove detected malware and restore original files
- **🤖 AI Decision Support** — Integrates LLM-based intelligence via LiteLLM for advanced threat assessment
- **📊 Status Tracking** — Full module lifecycle management (READY → RUNNING → COMPLETED/FAILED/CANCELLED)
- **🔌 Auto-Discovery** — Modules are automatically discovered and registered from the `src/modules` directory

## Architecture

```
Apollyon/
├── src/
│   ├── main.py              # Entry point - launches CLI application
│   ├── utils.py             # Helper utilities
│   ├── components/
│   │   ├── ui.py            # Terminal UI (banner, system info box)
│   │   ├── menu.py          # Interactive CLI menu system
│   │   ├── llm.py           # AI/LLM integration for decision support
│   │   └── ai_prompts.py    # AI prompt templates
│   └── modules/
│       ├── base.py          # Abstract BaseModule with standardized interface
│       ├── registry.py      # Module auto-discovery and registration
│       ├── movemenoreg.py   # MoveMenoreg malware scanner & disinfectant
│       └── jigsaw.py        # Jigsaw ransomware scanner & disinfectant & decryptor
```

### Module Interface

Every module extends `BaseModule` and must implement the methods documented in [docs/modules.md](docs/modules.md).

### Module Metadata

Each module defines a `MODULE_INFO` attribute. See [docs/modules.md](docs/modules.md) for the full reference.

## Installation

### Prerequisites

- **Python 3.14+** (64-bit)
- Administrator privileges (for system disinfection operations)

### Setup

```bash
# Clone the repository
git clone https://github.com/Nerveustech/Apollyon.git
cd Apollyon

# Install dependencies
pip install -r requirements.txt
```

### Environment Configuration (Optional)

For AI decision support features, create an `.env` file:

```bash
cp .env.example .env
```

Edit `.env` to add your LLM API key:

```env
LITELLM_API_KEY=your_api_key_here
LITELLM_MODEL=your_model_here
```

## Usage

### Running Apollyon

```bash
# From the project root
python -m src

# Or directly
python src/main.py
```

This launches the interactive CLI menu where you can:
1. View system information
2. Select modules to run
3. Choose target (system or USB)
4. Pick analysis or disinfection mode

### Operation Modes

#### Analysis Mode (Read-Only)
Scans for threats without making any changes. Returns findings in `ModuleResult`:

```python
from modules.registry import ModuleRegistry

registry = ModuleRegistry()
result = registry.get_module("movemenoreg_scanner").analyze(r"D:\")
print(result.data["findings"])  # List of detected threats
```

#### Disinfection Mode
Actively removes malware and restores original files:

```python
# Against a USB drive
result = registry.get_module("movemenoreg_scanner").disinfect_usb(r"D:\")

# Against the system
result = registry.get_module("movemenoreg_scanner").disinfect_system()
```

### Supported Targets

| Target | Description |
|--------|-------------|
| `system` | Windows system (AppData, Startup folder, running processes) |
| `usb` | Removable/USB drives (detected automatically via drive type) |

### Running Modules Independently

Each module can be executed without launching the CLI. You have two options:

#### Using Python Directly

Run modules directly with Python — useful for testing or quick execution:

```bash
# Run a specific module directly
python src/modules/jigsaw.py

# Run against a specific target
python -c "from src.modules.jigsaw import JigsawScanner; JigsawScanner().disinfect_system()"
```

Modules with an `if __name__ == '__main__'` block support direct execution and will run their default entry point method.

#### Compiled Executables

Modules can also be compiled into standalone executables using tools like **PyInstaller** or **Nuitka**, allowing them to run on systems without Python installed:

```bash
# Example with PyInstaller
pyinstaller --onefile --clean src/modules/jigsaw.py
```

This produces a single `.exe` (Windows) executable that can be distributed and run independently.

## Built-In Modules

| Module | Category | Description |
|--------|----------|-------------|
| `movemenoreg_scanner` | disinfection | Detects and removes MoveMenoreg malware from USB drives and Windows systems |

For full documentation on all modules, see [docs/modules.md](docs/modules.md).


## Developing Custom Modules

Create a new Python file in `src/modules/` (name must not start with `_`). The `ModuleRegistry` will auto-discover and register your module on startup. See [docs/modules.md](docs/modules.md) for the complete guide.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `psutil` | 7.2.2 | System/process information |
| `pywin32` | 311 | Windows API & COM object access |
| `python-dotenv` | >=1.0.1 | Environment variable management |
| `litellm` | >=1.83.7 | AI/LLM integration for decision support |

## License

This project is licensed under the [MIT License](LICENSE).

## Author

**Andrea Michael Maria Molino**