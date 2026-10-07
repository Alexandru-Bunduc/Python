# OwnRM - Custom Python Deletion Utility

OwnRM is a custom command-line utility built in Python that mimics and enhances the native `rm` command. It allows users to safely remove files and directories, offering advanced features like recursive deletion, simulated dry-runs, and detailed action logging. 

This project was developed in phases to demonstrate file system operations, error handling, and memory-safe recursive algorithms.

## Features

* **Basic Removal:** Safely delete individual files and empty directories.
* **Recursive Deletion (`-r`):** Traverse and delete full directory trees from the bottom up, ensuring nested files are removed before their parent folders.
* **Dry-Run Mode (`--dry-run`):** Preview exactly which files and folders will be deleted without making any actual changes to the file system.
* **Automated Logging:** Every successful deletion is automatically recorded in a local `deleted_log.txt` file, complete with session delimiters for easy tracking.
* **Safety First:** Built-in safeguards prevent the accidental deletion of non-empty directories unless the recursive flag is explicitly provided.

## Prerequisites

* **Python 3.x**
* No external libraries required. The script uses only built-in Python modules (`os`, `sys`).

## Usage

Open your terminal or command prompt and use the following syntax:

python OwnRM.py [-r] [--dry-run] <path_to_file_or_folder>

## Examples

1. Delete a single file or empty folder:
python OwnRM.py "C:\Users\Name\Desktop\file.txt"

2. Delete a folder and all its contents recursively:
python OwnRM.py -r "C:\Users\Name\Desktop\Old_Project"

3. Preview what would be deleted (without actually deleting anything):
python OwnRM.py --dry-run "C:\Users\Name\Desktop\file.txt"

4. Preview a full recursive deletion (Dry-Run + Recursive):
python OwnRM.py -r --dry-run "C:\Users\Name\Desktop\Old_Project"

