# Z3R0sec ThreatIntelTool

A Python tool to gather threat intelligence on IP addresses, domains, and file hashes using VirusTotal and AbuseIPDB APIs.

## Features

- **VirusTotal Search**: Checks the threat status of a given IP address, domain, or file hash using VirusTotal's API.
- **AbuseIPDB Lookup**: Retrieves the reputation score of an IP address using the AbuseIPDB API.

## Installation

### Prerequisites

Ensure that Python 3.x is installed on your system.

1. Clone the repository:
    ```sh
    git clone https://github.com/YourUsername/zs_ThreatIntelTool.git
    cd zs_ThreatIntelTool
    ```

2. Install required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Setting up API Keys

### VirusTotal API Key

To interact with VirusTotal's API, you will need to obtain an API key:

1. Go to the [VirusTotal website](https://www.virustotal.com/).
2. Create an account and log in.
3. Navigate to the API section under your profile.
4. Copy your API key.

### AbuseIPDB API Key

To use AbuseIPDB, follow these steps:

1. Visit [AbuseIPDB](https://www.abuseipdb.com/).
2. Sign up and log in.
3. Go to the API section to retrieve your API key.

### Define API Keys in the Command Line

Here’s how:

Set the VirusTotal API key:
- On Windows:
    ```sh
    set VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
    ```
- On Linux/MacOS:
    ```sh
    export VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
    ```

Set the AbuseIPDB API key:
- On Windows:
    ```sh
    set ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
    ```
- On Linux/MacOS:
    ```sh
    export ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
    ```

Replace `your_virustotal_api_key_here` and `your_abuseipdb_api_key_here` with the respective API keys.

## Usage

To run the script, use the following command:
```sh
python zs_threatinteltool.py
```

The tool will prompt you to enter an IP address, domain, or file hash to check against the APIs and display the results from both VirusTotal and AbuseIPDB.

### Example:
```sh
Enter an IP, domain, or file hash to check: 8.8.8.8
```

#### Output:
```sh
[VirusTotal] 8.8.8.8 Threat Analysis:
- Malicious: 0
- Suspicious: 0
- Undetected: 0

[AbuseIPDB] 8.8.8.8 Reputation Score: 0/100
```


