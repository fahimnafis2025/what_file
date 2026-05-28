# what_file
What_File: File Identity Triage Workbench
# 🔍 WHAT_FILE
> **Static File Identity Triage Workbench // Offline & Airgapped Mode**

`What_File` is an intuitive, single-click GUI orchestration workbench that automates static binary analysis. Built for SOC analysts, reverse engineers, and cybersecurity newcomers to instantly eliminate CLI tool fatigue, safely unpack file layers, and expose advanced malware evasion tactics. Currently compatiable with Ubuntu, Debian, Fedora, Arch and of course, Kali.

![What_File Dashboard](https://github.com/fahimnafis2025/what_file/blob/main/screenshot.png)

---

## ⚡ The Core Problem & Solution

* **The Old Way (CLI Fatigue):** Manually jumping across fragmented terminals running `file`, `strings`, `clamscan`, and `yara` while fighting messy, unparsed text streams.
* **The Investigator Way:** Drop the target file into `What_File`. Get automated layer unzipping, extension-spoofing logic checks, and signature-matching modules instantly inside a consolidated phosphor-green command cockpit.

---

## 🛠️ Matrix Capabilities

| Module | Core Intelligence |
| :--- | :--- |
| **📦 Archive Unpacking** | Detects `.zip` / `.tar` wrappers and safely unzips contents inside an isolated, auto-wiped memory directory. |
| **⚠️ Spoof Detection** | Audits internal binary headers (Magic Bytes) against file extensions to instantly catch masqueraded threats. |
| **🔑 Crypto Fingerprints** | Automatically calculates global unique cryptographic identifiers (`SHA-256`) for all nested components. |
| **🛡️ Local AV Scan** | Native pipeline integration with local threat definition databases (`ClamAV`) to match raw file bytes offline. |
| **🕸️ YARA Rule Mapping** | Dynamically compiles and fires deep pattern-matching rule trees across the entire decoupled file stream. |

---

## 📥 Deployment & Execution

### 1. Armor the Host (Dependencies)

Ensure your Linux base deployment environment (e.g., Kali Linux) has the core binaries installed:

```bash
sudo apt update && sudo apt install clamav yara exiftool binwalk file git -y
```

Update ClamAV's local virus definition database before first scan:

```bash
sudo freshclam
```

### 2. Clone the Repository

```bash
git clone https://github.com/fahimnafis2025/what_file.git
cd what_file
```

### 3. Install Python Dependencies

```bash
pip install customtkinter
```

> **Note:** `What_File` runs on Python 3.8+. No virtual environment required, but recommended for clean deployments.

### 4. Pull YARA Rules (Optional but Recommended)

On first launch, `What_File` will offer to auto-clone the community [Yara-Rules](https://github.com/Yara-Rules/rules) ruleset. To do it manually:

```bash
git clone https://github.com/Yara-Rules/rules.git yara_rules
```

Place the `yara_rules/` folder in the same directory as `app.py`.

### 5. Launch

```bash
python3 app.py
*You may need to create a venv to start
python3 -m venv venv
source venv/bin/activate
```

---

## 🖥️ Usage

```
1. Click  [ SELECT FILE ]   →  load any suspicious binary, archive, or document
2. Click  [ RUN ANALYSIS ]  →  all active modules fire automatically
3. Review the phosphor-green findings panel  →  each card is colour-coded by severity
4. At the end of the report, choose  [ DUMP TO .TXT ]  to export findings for archiving
```

**Supported file types:** `EXE` `DLL` `PDF` `DOCX` `ZIP` `TAR` `ELF` `MACH-O` `APK` `JAR` and anything the `file` utility can fingerprint.

---

## 🗂️ Project Structure

```
what_file/
├── app.py            # GUI layer — CustomTkinter phosphor-green cockpit
├── analyzer.py       # Engine layer — all static analysis modules
├── yara_rules/       # Community YARA ruleset (auto-cloned on first run)
│   └── index.yar
└── README.md
```

---

## 🔬 Test Without Real Malware

To verify your pipeline end-to-end without using a real malicious sample, use the **EICAR standard antivirus test file** — a 68-byte inert string recognised by every AV engine as a safe, controlled trigger:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Save it as `eicar.com` and run it through `What_File`. A correctly configured deployment will produce hits across the **ClamAV**, **YARA**, and **String Extraction** modules.

---

## ⚙️ Module Reference

### Archive Unpacking
Recursively extracts `.zip` and `.tar.*` containers into an isolated `tempfile.TemporaryDirectory()` that is cryptographically wiped on scope exit. Path traversal (`../`) and zip-bomb vectors (files > 100 MB uncompressed) are blocked before any bytes are written to disk.

### Extension Spoof Detection
Compares the declared file extension against the true magic-byte signature returned by `libmagic`. A `.png` that opens with a `PE32` header, for example, is immediately flagged as a masqueraded executable.

### Cryptographic Fingerprints
Streams `SHA-256` digests for every file in the scan scope — the root target and all extracted nested payloads — without loading the full binary into memory.

### Local AV Scan (ClamAV)
Pipes each file through `clamscan` using the locally installed definition database. Fully offline — zero telemetry, zero cloud lookups.

### YARA Rule Mapping
Fires the community `index.yar` ruleset against every file in scope. Results are deduplicated and capped at 15 matches per session to prevent report flooding on broad-spectrum rulesets.

### Network Indicator Extraction
Runs `strings` over raw bytes and applies regex filters to extract hardcoded `http(s)://` URLs and routable IPv4 addresses, filtering out version-number false positives.

---

## 🔒 Security & Ethics Notice

`What_File` performs **read-only static analysis only**. It does not execute, detonate, or modify any target file at any point. All extracted archive contents are written to a system-managed temporary directory and are irrecoverably deleted when analysis completes.

This tool is intended for:
- Defensive security research
- SOC triage workflows
- Malware analysis training

**Do not use `What_File` to analyse files you do not have explicit authorisation to inspect.**


---

<p align="center">
  <code>OFFLINE ● AIRGAPPED ● READ-ONLY</code><br/>
  <sub>Built for the terminal generation.</sub>
</p>
