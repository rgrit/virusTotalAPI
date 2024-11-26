# VirusTotal API IOC Scanner

This Python script scans Indicators of Compromise (IOCs) against the VirusTotal API to identify potentially malicious files or URLs. It processes IOCs from a CSV file, queries VirusTotal, and generates a report of flagged IOCs.

---

## Features
- Load VirusTotal API key securely from a local file.
- Process IOCs from a CSV file.
- Query the VirusTotal API for detailed information on each IOC.
- Handle rate-limiting with a configurable delay (default: 15 seconds).
- Save flagged IOCs with analysis details to an output CSV file.

---

## Prerequisites
- **Python 3.6+**
- A **VirusTotal API key** (you can obtain one [here](https://www.virustotal.com/)).

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/virusTotalAPI.git
   cd virusTotalAPI
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Place your VirusTotal API key in a file named `virustotal_api_key.txt` in the project directory.

---

## Usage
1. Prepare a CSV file named `ioc_list.csv` containing IOCs (e.g., file hashes or URLs). Ensure each IOC is listed on a new line.

2. Run the script:
   ```bash
   python script_name.py
   ```

3. The script will:
   - Read IOCs from the `ioc_list.csv` file.
   - Query VirusTotal for each IOC.
   - Save flagged IOCs with details to `flagged_iocs.csv`.

---

## Configuration
- **Input File**: Default is `ioc_list.csv`. Update the `input_file` variable in the script to change this.
- **Output File**: Default is `flagged_iocs.csv`. Update the `output_file` variable in the script to change this.
- **Rate Limit Delay**: Adjust the `time.sleep()` value to comply with your VirusTotal API tier.

---

## Output
The output CSV file includes:
- **IOC**: The scanned IOC (e.g., file hash).
- **Last Analysis Date**: The date of the last analysis on VirusTotal.
- **Malicious Count**: The number of engines that flagged the IOC as malicious.
- **VT Link**: Direct link to the VirusTotal analysis page for the IOC.

---

## Example
Input `ioc_list.csv`:
```
<hash_1>
<hash_2>
<hash_3>
```

Output `flagged_iocs.csv`:
| IOC       | Last Analysis Date | Malicious Count | VT Link                              |
|-----------|--------------------|-----------------|--------------------------------------|
| <hash_1>  | 2024-11-25         | 5               | https://www.virustotal.com/gui/...   |
| <hash_2>  | 2024-11-24         | 12              | https://www.virustotal.com/gui/...   |

---

## Known Issues
- **Rate Limiting**: The script includes a delay to handle free-tier API limits. Adjust the delay if you're using a premium API key.
- **File Not Found**: Ensure the `ioc_list.csv` and `virustotal_api_key.txt` files exist in the specified paths.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Contributions
