import os
import sys

def removed_files_log(message):
    with open("deleted_log.txt", "a", encoding="utf-8") as f:
        f.write(message + "\n")

def own_rm(inputPath, is_dry_run=False, is_recursive=False):
    if not os.path.exists(inputPath):
        print("The element does not exist.")
        return 

    try:
        if os.path.isfile(inputPath):
            if is_dry_run:
                print(f"[DRY-RUN MODE] This file would have been deleted: {inputPath}")
            else:
                os.remove(inputPath)
                print("The file has been deleted")
                removed_files_log(f"The file has been deleted: {inputPath}")
                removed_files_log(f"------THE PROCESS HAS FULLY DELETED {inputPath}------\n")
            
        elif os.path.isdir(inputPath):
            if not is_recursive:
                try:
                    os.rmdir(inputPath)
                    print(f"Empty folder has been deleted: {inputPath}")
                    removed_files_log(f"Empty folder has been deleted: {inputPath}")
                except OSError:
                    print(f"{inputPath} is not empty! Please use recursive mode(-r) to delete it.")
                return   
                
           
            for root, folders, files in os.walk(inputPath, topdown=False):
                for file_name in files:
                    full_file_path = os.path.join(root, file_name)
                    if is_dry_run:
                        print(f"[DRY-RUN MODE] The file would have been deleted: {full_file_path}")
                    else:
                        os.remove(full_file_path)   
                        print(f"File has been deleted: {full_file_path}")
                        removed_files_log(f"File has been deleted: {full_file_path}")     
                        
                for folder_name in folders:
                    full_folder_path = os.path.join(root, folder_name)
                    if is_dry_run:
                        print(f"[DRY-RUN MODE] This folder would have been deleted: {full_folder_path}")
                    else:
                        os.rmdir(full_folder_path) 
                        print(f"Folder has been deleted: {full_folder_path}")
                        removed_files_log(f"Folder has been deleted: {full_folder_path}") 
            
          
            if is_dry_run:
                print(f"[DRY-RUN MODE] The main folder would have been deleted: {inputPath}")
            else:
                os.rmdir(inputPath)
                print(f"The main folder has been deleted: {inputPath}")
                removed_files_log(f"The main folder has been deleted: {inputPath}") 
                removed_files_log(f"------THE PROCESS HAS FULLY DELETED {inputPath}------\n")           
                    
    except PermissionError:
        print(f"Permission error: you can't delete '{inputPath}'.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    arguments = sys.argv[1:]
    
    if len(arguments) == 0: 
        print("Tutorial: python OwnRM.py [-r] [--dry-run] <path_to_file_or_folder>")
        sys.exit() 
        
    dry_run_mode = "--dry-run" in arguments
    recursive_mode = "-r" in arguments
    
    
    target_path = ""
    for arg in arguments:
        if arg not in ["--dry-run", "-r"]:
            target_path = arg
            
    if target_path:
        own_rm(target_path, is_dry_run=dry_run_mode, is_recursive=recursive_mode)
    else:
        print("Please specify a valid path")