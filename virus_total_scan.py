# import pandas as pd
# import requests
#
# # Configure your VirusTotal API key
# API_KEY = "9229447d29480e31e1fe858995eb44a2e48609be1e719f98b53c02d9e2dbb0f0"
# API_URL = "https://www.virustotal.com/api/v3/files/"
#
#
# # Function to check IOC
# def check_ioc(ioc):
#     headers = {"x-apikey": API_KEY}
#     response = requests.get(API_URL + ioc, headers=headers)
#
#     if response.status_code == 200:
#         data = response.json()
#         # Extract malicious count
#         malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
#         return malicious_count
#     else:
#         print(f"Error {response.status_code} for IOC: {ioc}")
#         return None
#
#
# # Function to process CSV and check IOCs
# def process_csv(file_path, malicious_threshold):
#     # Read the CSV file
#     df = pd.read_csv(file_path)
#     if "IOC" not in df.columns:
#         print("The CSV file must contain an 'IOC' column.")
#         return
#
#     # Add a column for malicious counts
#     df["Malicious_Count"] = df["IOC"].apply(lambda x: check_ioc(x))
#
#     # Filter based on threshold
#     flagged = df[df["Malicious_Count"] >= malicious_threshold]
#
#     # Save the results
#     flagged.to_csv("flagged_iocs.csv", index=False)
#     print("Filtered IOCs saved to flagged_iocs.csv")
#
#
# # Example usage
# csv_file = "ioc_list.csv"  # Path to your CSV file
# malicious_threshold = 5  # Adjust the threshold as needed
# process_csv(csv_file, malicious_threshold)
import requests
import csv
import time


def load_api_key(file_path="virustotal_api_key.txt"):
    try:
        with open(file_path, "r") as file:
            api_key = file.read().strip()
            print(f"[INFO] API key loaded from {file_path}")
            return api_key
    except FileNotFoundError:
        print(f"[ERROR] API key file '{file_path}' not found.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error while loading API key: {e}")
        exit(1)


def query_virustotal(api_key, ioc):
    url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    headers = {"x-apikey": api_key}
    print(f"[DEBUG] Querying VirusTotal for IOC: {ioc}")
    print(f"[DEBUG] URL: {url}")
    print(f"[DEBUG] Headers: {headers}")

    try:
        response = requests.get(url, headers=headers)
        print(f"[DEBUG] Response status code: {response.status_code}")
        if response.status_code == 200:
            print(f"[INFO] IOC {ioc} found in VirusTotal database.")
            return response.json()
        elif response.status_code == 404:
            print(f"[WARNING] IOC {ioc} not found in VirusTotal database (Error 404).")
        else:
            print(f"[ERROR] Unexpected status code {response.status_code} for IOC {ioc}.")
            print(f"[DEBUG] Response content: {response.text}")
    except requests.RequestException as e:
        print(f"[ERROR] HTTP request failed for IOC {ioc}: {e}")
    return None


def read_iocs_from_csv(file_path):
    print(f"[INFO] Reading IOCs from file: {file_path}")
    iocs = []
    try:
        with open(file_path, "r") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:  # Skip empty rows
                    ioc = row[0].strip()
                    iocs.append(ioc)
                    print(f"[DEBUG] Loaded IOC: {ioc}")
        print(f"[INFO] Total IOCs loaded: {len(iocs)}")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error while reading IOCs: {e}")
        exit(1)
    return iocs


def process_iocs(iocs, api_key, output_file="flagged_iocs.csv"):
    flagged_iocs = []
    print(f"[INFO] Starting IOC processing. Total IOCs: {len(iocs)}")

    for i, ioc in enumerate(iocs, start=1):
        print(f"[INFO] Processing IOC {i}/{len(iocs)}: {ioc}")
        result = query_virustotal(api_key, ioc)

        if result:
            print(f"[INFO] IOC {ioc} flagged. Adding to results.")
            flagged_iocs.append({
                "IOC": ioc,
                "Last Analysis Date": result.get("data", {}).get("attributes", {}).get("last_analysis_date", "Unknown"),
                "Malicious Count": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", "Unknown"),
                "VT Link": f"https://www.virustotal.com/gui/file/{ioc}"
            })
        else:
            print(f"[INFO] Skipping IOC {ioc}. No results or not found.")

        print("[DEBUG] Sleeping for rate limit compliance (15 seconds).")
        time.sleep(15)  # VirusTotal free tier rate limit

    print(f"[INFO] Completed processing of all IOCs.")
    save_flagged_iocs(flagged_iocs, output_file)


def save_flagged_iocs(flagged_iocs, output_file):
    print(f"[INFO] Saving flagged IOCs to {output_file}")
    try:
        with open(output_file, "w", newline="") as csvfile:
            fieldnames = ["IOC", "Last Analysis Date", "Malicious Count", "VT Link"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for ioc in flagged_iocs:
                writer.writerow(ioc)
                print(f"[DEBUG] Written to file: {ioc}")
        print(f"[INFO] Successfully saved flagged IOCs to {output_file}")
    except Exception as e:
        print(f"[ERROR] Failed to save flagged IOCs: {e}")


if __name__ == "__main__":
    print("[INFO] Starting VirusTotal scanning script.")
    api_key = load_api_key()
    input_file = r"/\ioc_list.csv"

    iocs = read_iocs_from_csv(input_file)
    process_iocs(iocs, api_key)
    print("[INFO] Script execution complete.")
