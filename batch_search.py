import csv
import json
import subprocess
import sys

# Input and output file paths
INPUT_FILE = f"/home/data/{sys.argv[1]}" 
OUTPUT_FILE = "/home/data/vulnerabilities.csv"

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
    command = f"/home/search_vulns/search_vulns.py {' '.join(queries)} --use-created-cpes -f json"
    
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
    """Extracts vulnerability information and converts it into a list of dictionaries."""
    extracted_data = []
    
    for software, details in json_data.items():
        version = details.get("cpe", "").split(":")[5]
        vulns = details.get("vulns", {})
        
        for cve_id, vuln_details in vulns.items():
            extracted_data.append({
                "name": software,
                "version": version,
                "cve_id": cve_id,
                "aliases": ", ".join(vuln_details.get("aliases", [])),
                "severity": vuln_details.get("cvss", "N/A"),
                "known_exploited": vuln_details.get("cisa_known_exploited", False),
                "published": vuln_details.get("published", "N/A"),
                "href": vuln_details.get("href", "N/A")
            })
    
    return extracted_data

def write_csv(data, output_file):
    """Writes extracted data to a CSV file."""
    fieldnames = ["name", "version", "cve_id", "aliases", "severity", "known_exploited", "published", "href"]
    
    try:
        with open(output_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            
        print(f"CSV file saved: {output_file}")
    except Exception as e:
        print(f"Error writing CSV file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    queries = read_input_file(INPUT_FILE)
    json_data = run_search_vulns(queries)
    parsed_data = parse_json_data(json_data)
    write_csv(parsed_data, OUTPUT_FILE)
