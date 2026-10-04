import psutil
import argparse
import sys
import subprocess

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

def run_process(args):
    cmd = [args.path] + args.cmd_args
    try:
        proc = subprocess.Popen(cmd, cwd=args.cwd)
        print(f"Process started successfully. PID: {proc.pid}")
        sys.exit(0) 
    except Exception as e:
        print(f"Error starting process: {e}")
        sys.exit(1)


def kill_process(args):
    try:
        proc = psutil.Process(args.pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
            print(f"Process with PID {args.pid} was gracefully terminated.")
        except psutil.TimeoutExpired:
            proc.kill()
            print(f"Process with PID {args.pid} was forcibly killed.")
        sys.exit(0)
    except psutil.NoSuchProcess:
        print(f"Error: No process found with PID {args.pid}.")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"Error: Access denied to kill process {args.pid} (try running terminal as Administrator).")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(description="Process Manager CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
   
    subparsers.add_parser("view", help="Shows a table with all the active processes")
    run_parser = subparsers.add_parser("run", help="Start a new process (non-blocking)")
    run_parser.add_argument("path", help="Path to the executable to start")
    run_parser.add_argument("cmd_args", nargs=argparse.REMAINDER, help="Optional arguments for the executable")
    run_parser.add_argument("-cwd", "--cwd", help="Specify an optional working directory", default=None)

    kill_parser = subparsers.add_parser("kill", help="Terminate a process by its PID")
    kill_parser.add_argument("pid", type=int, help="The PID of the process to terminate")

    args = parser.parse_args()
    
    if args.command == "view":
        view_processes()
    elif args.command == "run":
        run_process(args)
    elif args.command == "kill":
        kill_process(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()