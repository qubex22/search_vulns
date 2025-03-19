import csv
import json
import subprocess
import sys
import re

# Input and output file paths
f_name = sys.argv[1]
INPUT_FILE = f"/home/data/{f_name}"
OUTPUT_FILE = f"/home/data/vulnerabilities_{f_name}.csv"
WARNING_FILE = "/home/data/warnings_{f_name}.log"

def read_input_file(file_path):
    """Reads vendor, product, and version information from a file."""
    queries = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                query = line.strip()
                if query:
                    queries.append(f"-q \"{query}\"")
        return queries
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        sys.exit(1)

def run_search_vulns(queries):
    """Runs search_vulns.py and captures JSON output."""
    command = f"search_vulns {' '.join(queries)} --use-created-cpes -f json"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Command stdout: {e.stdout}")
        print(f"Command stderr: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}")
        sys.exit(1)

def parse_json_data(json_data):
    """Extracts vulnerability information and converts it into a list of dictionaries.
       Also logs warnings separately.
    """
    extracted_data = []
    warnings = []

    for software, details in json_data.items():
        # Check if the entry contains a warning message string instead of vulnerability data
        if isinstance(details, str) and details.startswith("Warning"):
            warnings.append(f"{software}: {details}")
            continue  # Skip this entry

        # Extract version from CPE if available
        searched_cpes = details.get("cpe", "")
        vendor = details.get("cpe", "").split(":")[3] if "cpe" in details else "N/A"
        product = version = details.get("cpe", "").split(":")[4] if "cpe" in details else "N/A"
        version = details.get("cpe", "").split(":")[5] if "cpe" in details else "N/A"
        vulns = details.get("vulns", {})

        for cve_id, vuln_details in vulns.items():
            extracted_data.append({
                "query": software,
                "vendor": vendor,
                "product": product,
                "version": version,
                "cve_id": cve_id,
                "vuln_match_reason": vuln_details.get("vuln_match_reason", "N/A"),
                "aliases": ", ".join(vuln_details.get("aliases", [])),
                "severity": vuln_details.get("cvss", "N/A"),
                "known_exploited": vuln_details.get("cisa_known_exploited", False),
                "published": vuln_details.get("published", "N/A"),
                "href": vuln_details.get("href", "N/A"),
                "searched_cpes": searched_cpes
            })

    return extracted_data, warnings

def write_csv(data, output_file):
    """Writes extracted data to a CSV file."""
    fieldnames = ["query", "vendor", "product", "version", "cve_id", "vuln_match_reason", "aliases", "severity", "known_exploited", "published", "href","searched_cpes"]

    try:
        with open(output_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        print(f"CSV file saved: {output_file}")
    except Exception as e:
        print(f"Error writing CSV file: {e}")
        sys.exit(1)

def write_warnings(warnings, output_file):
    """Writes warnings to a log file."""
    if warnings:
        try:
            with open(output_file, "w") as file:
                for w in warnings:
                    file.write(w + "\n")
            print(f"Warnings saved to: {output_file}")
        except Exception as e:
            print(f"Error writing warnings file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    queries = read_input_file(INPUT_FILE)
    json_data = run_search_vulns(queries)
    parsed_data, warnings = parse_json_data(json_data)
    write_csv(parsed_data, OUTPUT_FILE)
    write_warnings(warnings, WARNING_FILE)
