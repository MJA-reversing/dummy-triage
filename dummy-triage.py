import sys
import os
import re
import hashlib
import pefile
import json

def getfile():
    if len(sys.argv) != 2:
        print("usage: python dummy-triage.py <file_or_directory>")
        sys.exit(1)

    input_path = sys.argv[1]

    if not os.path.exists(input_path):
        print(f"Error: '{input_path}' does not exist.")
        sys.exit(1)

    return input_path

def gethash(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            md5_hash.update(data)
            sha256_hash.update(data)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def extract_strings(file_path):
    result = {
        "urls": [],
        "ips": [],
        "emails": [],
        "suspicious": []       
    }
    with open(file_path, "rb") as f:
        data = f.read()
        strings = re.findall(b"[ -~]{4,}", data)
    for s in strings:
        decoded = s.decode("utf-8", errors="ignore")

        if len(decoded.strip()) < 6:
            continue

        if not any(c.isalpha() for c in decoded):
            continue

        if re.match(r"https?://[a-zA-Z0-9./\-_%]+", decoded):
            result["urls"].append(decoded)
        elif re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", decoded):
            result["ips"].append(decoded)
        elif re.match(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", decoded):
            result["emails"].append(decoded)
        elif any(x in decoded.lower() for x in ["cmd", "powershell", "wget"]):
            result["suspicious"].append(decoded)
    return result

def process_directory(directory):
    print(f"[+] Processing directory: {directory}")

    all_reports = []

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        if not os.path.isfile(file_path):
            continue

        try:
            print(f"[+] Processing: {filename}")
            report = build_report(file_path)
            all_reports.append(report)

        except Exception as e:
            print(f"[!] Error processing {filename}: {e}")

    return all_reports

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except:
        return {"error": "Not a PE file"}

    imports = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())

    return {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "imports": list(set(imports))
    }

def build_report(file_path):
    report = {}

    report["file"] = file_path
    report["hashes"] = gethash(file_path)
    report["strings"] = extract_strings(file_path)
    report["pe_analysis"] = analyze_pe(file_path)

    return report

def save_batch_report(reports, directory):
    output = {
        "total_files": len(reports),
        "reports": reports
    }

    name = os.path.basename(directory.rstrip("/")) + "_batch_report.json"

    with open(name, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Batch report saved to {name}")

def save_report(report, file_path):
    base = os.path.basename(file_path)
    name = base + "_report.json"

    with open(name,"w") as f:
        json.dump(report, f, indent=4)

    print(f"Report save to {name}")

def main():
    input_path = getfile()

    if os.path.isfile(input_path):
        report = build_report(input_path)
        save_report(report, input_path)

    elif os.path.isdir(input_path):
        reports = process_directory(input_path)
        save_batch_report(reports, input_path)

    else:
        print("Invalid input")

if __name__ == "__main__":
    main()
