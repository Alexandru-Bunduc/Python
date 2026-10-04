import psutil
import argparse

def view_processes():
    
    print(f"{'PID':<8} | {'Name':<25} | {'Path / Cmdline'}")
    print("-" * 100)
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            pid = info.get('pid', 'N/A')
            name = info.get('name') or "N/A"
            exe = info.get('exe')
            cmdline = info.get('cmdline')
            
            
            if cmdline:
                path_info = " ".join(cmdline)
            elif exe:
                path_info = exe
            else:
                path_info = "N/A"
                
            
            name = name[:25]
            path_info = path_info[:100]
            
            print(f"{pid:<8} | {name:<25} | {path_info}")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def main():
    parser = argparse.ArgumentParser(description="Process Manager CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
   
    subparsers.add_parser("view", help="Shows a table with all the active processes")
    
    args = parser.parse_args()
    
    if args.command == "view":
        view_processes()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()