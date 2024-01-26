import sys
import os
import hashlib
import zipfile
from datetime import datetime
import argparse
import subprocess
import json

def run_windows_defender_scan(file_path: str) -> str:
    """Run Windows Defender scan on file_path and return the result.

    Args:
        file_path (str): Path to the file to be scanned.

    Returns:
        str: Scan result, "CLEAN" or "INFECTED".
    """
    cmd = f'"{os.environ["ProgramFiles"]}\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File "{os.path.abspath(file_path)}"'
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if "found no threats" in result.stdout.decode():
        return "CLEAN"
    else:
        return "INFECTED"

def scan_directory(directory, user_id):
    file_info = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            orig_file_path = os.path.join(root, file)
            file_path = os.path.abspath(orig_file_path)
            virus_scan = run_windows_defender_scan(file_path)

            if virus_scan == "CLEAN":
                with open(file_path, "rb") as f:
                    bytes = f.read()
                    readable_hash = hashlib.sha256(bytes).hexdigest()

                file_info.append({
                    "file_path": os.path.normpath(orig_file_path),
                    "user_id": user_id,
                    "virus_scan": virus_scan,
                    "hash": readable_hash
                })
            else:
                print(f"Virus found in {file_path}!")
                sys.exit(1)


    date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"log__send__{date_time_str}.txt"
    with open(log_filename, "w") as log_file:
            json.dump(file_info, log_file)

    zip_filename = f"transfer__{date_time_str}.zip"
    with zipfile.ZipFile(zip_filename, "w") as zipf:
        for root, dirs, files in os.walk(directory):
            for file in files:
                zipf.write(os.path.join(root, file))
        zipf.write(log_filename)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a directory for viruses, generate a log, and zip the contents.')
    parser.add_argument('directory', type=str, help='The directory to scan')
    
    # get user id from os
    user_id = os.getlogin()

    args = parser.parse_args()

    scan_directory(args.directory, user_id)