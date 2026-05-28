import os
import re
import shutil
import subprocess
import hashlib
import tempfile
import zipfile
import tarfile

class FileAnalyzerEngine:

    def __init__(self):
        # Strictly offline analysis tools mapped to package managers
        self.required_tools = {
            "file": "apt",
            "strings": "apt",
            "exiftool": "apt",
            "binwalk": "apt",
            "clamscan": "apt",     # Local offline Antivirus
            "yara": "apt",         # Pattern matching engine
            "git": "apt",          # Needed to download YARA rules
        }
        # Default directory to store downloaded YARA rules
        self.yara_rules_dir = os.path.abspath(os.path.join(os.getcwd(), "yara_rules"))

    def get_missing_tools(self) -> list:
        missing = []
        for tool in self.required_tools.keys():
            if shutil.which(tool) is None:
                missing.append(tool)
        return missing

    def install_tools(self, tools_to_install: list) -> bool:
        apt_packages = []
        for tool in tools_to_install:
            if self.required_tools.get(tool) == "apt":
                if tool == "clamscan":
                    apt_packages.append("clamav")
                else:
                    apt_packages.append(tool)
        try:
            if apt_packages:
                print(f"[+] Installing system packages: {apt_packages}")
                subprocess.run(["pkexec", "apt-get", "update", "-y"], check=True, shell=False)
                install_cmd = ["pkexec", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y"] + apt_packages
                subprocess.run(install_cmd, check=True, shell=False)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Installation failed: {e}")
            return False

    def setup_yara_rules(self, custom_path: str = None) -> bool:
        if custom_path and os.path.exists(custom_path):
            self.yara_rules_dir = os.path.abspath(custom_path)
            return True
        if os.path.exists(self.yara_rules_dir) and os.listdir(self.yara_rules_dir):
            return True
        try:
            subprocess.run(["git", "clone", "https://github.com/Yara-Rules/rules.git", self.yara_rules_dir], check=True, shell=False)
            return True
        except subprocess.CalledProcessError:
            return False

    def _run_command(self, cmd_prefix: list, file_path: str, custom_timeout: int = 60) -> str:
        try:
            safe_target = os.path.abspath(file_path)
            full_cmd = cmd_prefix + [safe_target]
            result = subprocess.run(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=custom_timeout, shell=False
            )
            return result.stdout
        except FileNotFoundError:
            return ""  
        except subprocess.TimeoutExpired:
            return "Analysis timed out (Potential decompression bomb)."
        except Exception as e:
            return f"Error executing tool: {str(e)}"

    def _generate_sha256(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def _detect_extension_spoofing(self, filename: str, magic_string: str) -> str:
        """Compares file extension against true magic bytes to detect spoofing."""
        ext = os.path.splitext(filename)[1].lower()
        magic_lower = magic_string.lower()
        
        # Mapping of common extensions to what their magic bytes SHOULD contain
        expected_signatures = {
            ".png": ["png", "image data"],
            ".jpg": ["jpeg", "image data"],
            ".jpeg": ["jpeg", "image data"],
            ".pdf": ["pdf document"],
            ".exe": ["pe32", "executable"],
            ".dll": ["pe32", "executable", "dll"],
            ".zip": ["zip archive"],
            ".txt": ["text", "ascii", "unicode"]
        }

        if ext in expected_signatures:
            # If none of the expected keywords are in the magic string, it's a spoof!
            if not any(keyword in magic_lower for keyword in expected_signatures[ext]):
                return f"[{filename}] Claimed: {ext.upper()} | Actual: {magic_string.split(',')[0]}"
        return ""

    def _safe_extract(self, archive_path: str, temp_dir: str) -> list:
        """Safely unzips files, preventing path traversal and zip bombs."""
        extracted_files = []
        try:
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    for member in zf.infolist():
                        # Prevent directory traversal (e.g. extracting to ../../../etc/passwd)
                        if member.filename.startswith('/') or '..' in member.filename:
                            continue
                        # Prevent zip bomb (skip unusually large individual files > 100MB)
                        if member.file_size > 100 * 1024 * 1024:
                            continue
                        extracted_path = zf.extract(member, temp_dir)
                        extracted_files.append(extracted_path)
            
            elif tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, 'r:*') as tf:
                    for member in tf.getmembers():
                        if member.name.startswith('/') or '..' in member.name:
                            continue
                        if member.size > 100 * 1024 * 1024:
                            continue
                        tf.extract(member, temp_dir)
                        extracted_files.append(os.path.join(temp_dir, member.name))
        except Exception as e:
            pass # Failsafe: If extraction fails due to corruption, move on.
        
        return [f for f in extracted_files if os.path.isfile(f)]

    def analyze(self, target_file: str) -> dict:
        if not os.path.exists(target_file):
            return {"Error": "File does not exist."}

        insights = {}
        
        # We will use a temporary directory to handle extracted files.
        # This auto-deletes itself and all contents when the block finishes!
        with tempfile.TemporaryDirectory() as temp_dir:
            
            # List of files we need to scan (Starts with just the root file)
            files_to_scan = [target_file]
            
            # Attempt safe extraction
            extracted = self._safe_extract(target_file, temp_dir)
            if extracted:
                files_to_scan.extend(extracted)
                insights["Archive Unpacking"] = {
                    "explanation": "Detected an archive. Automatically extracted hidden contents for deep analysis:",
                    "data": [f"Extracted {len(extracted)} nested file(s) for scanning."]
                }

            # Data aggregators
            hashes = {}
            file_identities = {}
            spoof_warnings = []
            av_hits = {}
            yara_hits = []
            all_urls = []
            all_ips = []

            # --- PROCESS EVERY FILE (ROOT + EXTRACTED) ---
            for current_file in files_to_scan:
                display_name = os.path.basename(current_file)
                if current_file == target_file:
                    display_name = f"{display_name} (ROOT)"

                # 1. Hashing
                file_hash = self._generate_sha256(current_file)
                if file_hash:
                    hashes[display_name] = file_hash

                # 2. Magic Bytes & Spoof Detection
                magic_output = self._run_command(["file", "-b"], current_file).strip()
                if magic_output:
                    file_identities[display_name] = magic_output
                    spoofing = self._detect_extension_spoofing(display_name, magic_output)
                    if spoofing:
                        spoof_warnings.append(spoofing)

                # 3. Local Antivirus (Clamscan)
                clam_output = self._run_command(["clamscan", "--no-summary"], current_file)
                if "FOUND" in clam_output:
                    match = re.search(r":\s+(.+?)\s+FOUND", clam_output)
                    if match:
                        av_hits[display_name] = match.group(1)

                # 4. YARA Matches
                index_file = os.path.join(self.yara_rules_dir, "index.yar")
                if os.path.exists(self.yara_rules_dir) and os.path.exists(index_file):
                    yara_output = self._run_command(["yara", "-w", index_file], current_file)
                    matches = [line.split()[0] for line in yara_output.split("\n") if line.strip()]
                    if matches:
                        yara_hits.extend([f"[{display_name}] Rule triggered: {m}" for m in matches])

                # 5. Strings / Network parsing
                strings_output = self._run_command(["strings"], current_file)
                urls = re.findall(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}[^\s]*", strings_output)
                ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", strings_output)
                
                # Filter out obvious false positive IPs like version numbers
                valid_ips = [ip for ip in ips if not ip.startswith("0.") and not ip.startswith("255.")]
                
                all_urls.extend(urls)
                all_ips.extend(valid_ips)

            # --- POPULATE GUI INSIGHTS MAPPING ---
            if spoof_warnings:
                insights["⚠️ Extension Spoofing Detected"] = {
                    "explanation": "CRITICAL: The file extension does not match its true internal magic bytes. This is a common evasion tactic.",
                    "data": spoof_warnings
                }

            if hashes:
                insights["Cryptographic Intel"] = {
                    "explanation": "SHA-256 fingerprints for the archive and all nested payloads:",
                    "data": hashes
                }

            if av_hits:
                insights["Local Antivirus Scan"] = {
                    "explanation": "ClamAV matched raw file bytes to known malware signatures:",
                    "data": av_hits
                }

            if yara_hits:
                insights["YARA Rule Matches"] = {
                    "explanation": "Raw bytes matched known community malware family patterns:",
                    "data": list(set(yara_hits))[:15]
                }

            if file_identities:
                insights["File Identification"] = {
                    "explanation": "True file types identified by inspecting internal magic headers:",
                    "data": file_identities
                }

            # Network Indicators Logic
            net_data = {}
            if all_urls:
                net_data["URLs Found"] = list(set(all_urls))[:15]
            if all_ips:
                net_data["IP Addresses Found"] = list(set(all_ips))[:15]

            if net_data:
                insights["Network Indicators (Plaintext)"] = {
                    "explanation": "Hardcoded text structures referencing web links or endpoints across all files:",
                    "data": net_data
                }

        return insights
