import os
import hashlib
import zipfile
import argparse
import json
import sys
import subprocess
from datetime import datetime

log_data = []

def write_log_file():
    date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"log__receive__{date_time_str}.txt"
    with open(log_filename, "w") as log_file:
        log_file.write("\n".join(log_data))

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

def receive_files(zip_file_path, target_directory):

    log_file_name = None
    with zipfile.ZipFile(zip_file_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.startswith('log__'):
                log_file_name = name
                break

    with zipfile.ZipFile(zip_file_path, 'r') as zipf:
        zipf.extract(log_file_name, path=".")

    with open(log_file_name, 'r') as log_file:
        file_info = json.load(log_file)

    if any(info['virus_scan'] == 'INFECTED' for info in file_info):
        print('Error: One or more files in the zip file are infected.')
        write_log_file()
        sys.exit(1)

    for info in file_info:
        file_path = os.path.normpath(info['file_path'])
        while "\\" in file_path:
            file_path = file_path.replace("\\", "/")

        with zipfile.ZipFile(zip_file_path, 'r') as zipf:
            zipf.extract(file_path, path=target_directory)

        with open(os.path.join(target_directory, file_path), 'rb') as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest()

        if readable_hash != info['hash']:
            print(f"Error: The hash of {file_path} does not match the hash in the log file.")
            sys.exit(1)

        scan_result = run_windows_defender_scan(os.path.join(target_directory, file_path))
        if scan_result == "INFECTED":
            print(f"Error: Virus found in {info['file_path']} during secondary scan!")
            log_data.append(f"Virus found in {info['file_path']} during secondary scan!")
            sys.exit(1)
        else:
            log_data.append(f"Successfully extracted {os.path.join(target_directory, file_path)}:  hash matches and no virus found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Receive a zip file and extract its contents.')
    parser.add_argument('zip_file_path', type=str, help='The path to the zip file')
    parser.add_argument('target_directory', type=str, help='The directory to extract the files to')
    args = parser.parse_args()

    log_data.append("User: " + os.getlogin())
    log_data.append("Zip file path: " + args.zip_file_path)
    log_data.append("Target directory: " + args.target_directory)

    receive_files(args.zip_file_path, args.target_directory)

    write_log_file()