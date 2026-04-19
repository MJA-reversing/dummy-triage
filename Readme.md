# Dummy Triage

A simple lightweight Python-based malware triage tool for quickly extracting basic indicators and metadata from binary files.

---

## Overview

As a malware analyst there are a million triage tools that all do the dame thing. This project is a way that I can write simple straight forward code to achieve the intial triage process. Dummy Triage automates common first-step analysis tasks performed during malware triage. It is designed to provide quick visibility into a file’s characteristics without deep reverse engineering.

The tool currently supports:

* File hashing (MD5, SHA256)
* String extraction and basic indicator parsing
* PE (Portable Executable) metadata analysis
* Structured JSON reporting

---

## Features

* **Hashing**

  * Generates MD5 and SHA256 hashes for file identification

* **String Extraction**

  * Extracts printable strings from binaries
  * Identifies:

    * URLs
    * IP addresses
    * Email addresses
    * Suspicious command-related strings (e.g., `cmd`, `powershell`, `wget`)

* **PE Analysis**

  * Extracts:

    * Entry point
    * Image base
    * Imported functions

* **Report Generation**

  * Outputs results to a JSON file for easy review and further processing

---

## Usage

```bash
python dummy-triage.py <binary_file>
```

Example:

```bash
python dummy-triage.py sample.exe
```

---

## Output

The tool generates a JSON report in the current directory:

```bash
sample.exe_report.json
```

Example structure:

```json
{
    "file": "sample.exe",
    "hashes": {
        "md5": "...",
        "sha256": "..."
    },
    "strings": {
        "urls": [],
        "ips": [],
        "emails": [],
        "suspicious": []
    },
    "pe_analysis": {
        "entry_point": "...",
        "image_base": "...",
        "imports": []
    }
}
```

---

## Requirements

* Python 3.x
* `pefile`

Install dependencies:

```bash
pip install pefile
```

---

## Limitations

* Currently optimized for PE (Windows) binaries
* String extraction is basic and may include noise
* No dynamic analysis or behavioral execution

---

## Future versions

Planned improvements include:

* ELF and Mach-O support
* Improved string filtering and parsing
* Suspicious import detection
* YARA rule integration
* Batch file processing

---

## Disclaimer

This tool is intended for educational and research purposes only. Use responsibly when analyzing unknown or potentially malicious files.

---

## Author

Matt Allan
