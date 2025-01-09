import requests
import sys
import os

# API keys 
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Color codes for aesthetics
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

def print_separator():
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")

def check_virustotal(query): 
    print_separator()
    url = f"https://www.virustotal.com/api/v3/search?query={query}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "data" in data:
            positives = data["data"][0]["attributes"].get("last_analysis_stats", {})
            print(f"{Colors.BLUE}[VirusTotal] {query} Threat Analysis:{Colors.RESET}")
            print(f"  - {Colors.GREEN}Malicious:{Colors.RESET} {positives.get('malicious', 0)}")
            print(f"  - {Colors.YELLOW}Suspicious:{Colors.RESET} {positives.get('suspicious', 0)}")
            print(f"  - {Colors.RED}Undetected:{Colors.RESET} {positives.get('undetected', 0)}")
        else:
            print(f"{Colors.RED}[VirusTotal] No results found for {query}.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[VirusTotal] Error: {response.status_code}{Colors.RESET}")

def check_abuseipdb(ip):
    print_separator()
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        print(f"{Colors.BLUE}[AbuseIPDB] {ip} Reputation Score:{Colors.RESET} {Colors.GREEN}{abuse_score}/100{Colors.RESET}")
    else:
        print(f"{Colors.RED}[AbuseIPDB] Error: {response.status_code}{Colors.RESET}")

if __name__ == "__main__":
    print(f"{Colors.BOLD}{Colors.CYAN}Z3R0sec ThreatIntelTool!{Colors.RESET}")
    query = input(f"{Colors.BOLD}Enter an IP, domain, or file hash to check:{Colors.RESET} ").strip()
    
    # Determine if user input is IP, domain, or file hash
    if "." in query and not query.endswith(".com"):  
        check_abuseipdb(query)  # Queries AbuseIPDB for IP reputation
    
    check_virustotal(query)  # Queries VirusTotal for all types
    print_separator()