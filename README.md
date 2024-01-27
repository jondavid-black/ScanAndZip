# ScanAndZip
Simple python program to scan and package files for transfer.

The intent is to provide a means of automating secure file transfer across disconnected systems.  The critical steps involved are to scan files prior to transfer and after transfer while logging the details of the transfer.  The actual file transfer is left as a manual process.

For our purposes we are targeting a Windows environment with Windows Defender virus scanning available.

## Usage

First use the send program to scan and package files for transfer. This will create a zip file in the current directory.

```ps1
py send.py <directory_with_files_to_transfer>
```
Then transfer the zip file to the destination machine. Once the zip file is on the destination machine, use the receive program to unpack the files.

```ps1
py receive.py <zip_file_to_unpack> <target_directory_for_files>
```


