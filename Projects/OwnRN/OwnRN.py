import os
import sys

def own_rm(inputPath):
    if not os.path.exists(inputPath):
        print("The element does not exist.")
        return 

    try:
        if os.path.isfile(inputPath):
            os.remove(inputPath)
            print("The file has been deleted")
            
        elif os.path.isdir(inputPath):
            try:
                os.rmdir(inputPath)
                print(f"Empty folder has been deleted: {inputPath}")
            except OSError:
                print(f"{inputPath} is not empty!")
                
    except PermissionError:
        print(f"Permission error: you can't delete '{inputPath}'.")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
        own_rm(target_path)
    else:
        print("Tutorial: python OwnRN.py <path_to_file_or_folder>")