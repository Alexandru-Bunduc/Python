import psutil
import argparse
import subprocess
import sys
import time

# ==========================================
# PHASE 1+4: View + Metrics and Sorts
# ==========================================
def view_processes(args):
    
    procs = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info']))
    
    for p in procs:
        try:
            
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    # Short sampling window (seconds)
    time.sleep(0.1)
    
    process_list = []
    for p in procs:
        try:
            info = p.info
            # Calculate how much of the CPU was consumed in 0.1 seconds
            cpu = p.cpu_percent(interval=None)
            mem_bytes = info['memory_info'].rss if info.get('memory_info') else 0
            mem_mb = mem_bytes / (1024 * 1024)
            pid = info.get('pid', 0)
            name = info.get('name') or "N/A"
            exe = info.get('exe')
            cmdline = info.get('cmdline')
            
            if cmdline:
                path_info = " ".join(cmdline)
            elif exe:
                path_info = exe
            else:
                path_info = "N/A"
                
            process_list.append({
                'pid': pid,
                'cpu': cpu,
                'mem': mem_mb,
                'name': name[:20],
                'path': path_info[:80]
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

   
    sort_key = args.sort
    process_list.sort(key=lambda x: x[sort_key], reverse=args.desc)
    
    print(f"{'PID':<8} | {'CPU%':<6} | {'Mem(MB)':<8} | {'Name':<20} | {'Path / Cmdline'}")
    print("-" * 130)
    for p in process_list:
        print(f"{p['pid']:<8} | {p['cpu']:<6.1f} | {p['mem']:<8.1f} | {p['name']:<20} | {p['path']}")

# ==========================================
# PHASE 2: Run / Kill
# ==========================================
def run_process(args):
    cmd = [args.path] + args.cmd_args
    try:
        proc = subprocess.Popen(cmd, cwd=args.cwd)
        print(f"Success: Process started. PID: {proc.pid}")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting process: {e}")
        sys.exit(1)

def kill_process(args):
    try:
        proc = psutil.Process(args.pid)
        proc.terminate() # Graceful terminate
        try:
            proc.wait(timeout=3)
            print(f"Success: PID {args.pid} gracefully terminated.")
        except psutil.TimeoutExpired:
            proc.kill() # Force kill
            print(f"Success: PID {args.pid} forcibly killed.")
        sys.exit(0)
    except psutil.NoSuchProcess:
        print(f"Error: PID {args.pid} not found.")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"Error: Insufficient permission to kill PID {args.pid}.")
        sys.exit(1)

# ==========================================
# PHASE 3: Suspend / Resume
# ==========================================
def suspend_process(args):
    try:
        proc = psutil.Process(args.pid)
        if proc.status() == psutil.STATUS_STOPPED:
            print(f"Notice: PID {args.pid} is already suspended.")
            sys.exit(0)
            
        proc.suspend()
        print(f"Success: PID {args.pid} suspended.")
        sys.exit(0)
    except psutil.NoSuchProcess:
        print(f"Error: PID {args.pid} not found.")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"Error: Insufficient permission to suspend PID {args.pid}.")
        sys.exit(1)

def resume_process(args):
    try:
        proc = psutil.Process(args.pid)
        if proc.status() != psutil.STATUS_STOPPED:
            print(f"Notice: PID {args.pid} is not suspended.")
            sys.exit(0)
            
        proc.resume()
        print(f"Success: PID {args.pid} resumed.")
        sys.exit(0)
    except psutil.NoSuchProcess:
        print(f"Error: PID {args.pid} not found.")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"Error: Insufficient permission to resume PID {args.pid}.")
        sys.exit(1)

# ==========================================
# CLI ARGPARSE CONFIGURATION
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="Process Manager CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # View (Phase 1 & 4)
    view_parser = subparsers.add_parser("view", help="Display active processes with CPU and Mem usage")
    view_parser.add_argument("-sort", choices=["cpu", "mem", "pid"], default="pid", help="Sort criteria")
    view_parser.add_argument("-desc", action="store_true", help="Sort in descending order")
    
    # Run (Phase 2)
    run_parser = subparsers.add_parser("run", help="Start a new process")
    run_parser.add_argument("path", help="Path to the executable")
    run_parser.add_argument("cmd_args", nargs=argparse.REMAINDER, help="Optional arguments")
    run_parser.add_argument("-cwd", "--cwd", help="Optional working directory", default=None)
    
    # Kill (Phase 2)
    kill_parser = subparsers.add_parser("kill", help="Terminate a process")
    kill_parser.add_argument("pid", type=int, help="PID of the process")
    
    # Suspend (Phase 3)
    suspend_parser = subparsers.add_parser("suspend", help="Pause a process")
    suspend_parser.add_argument("pid", type=int, help="PID of the process")
    
    # Resume (Phase 3)
    resume_parser = subparsers.add_parser("resume", help="Resume a paused process")
    resume_parser.add_argument("pid", type=int, help="PID of the process")
    
    args = parser.parse_args()
    
    if args.command == "view":
        view_processes(args)
    elif args.command == "run":
        run_process(args)
    elif args.command == "kill":
        kill_process(args)
    elif args.command == "suspend":
        suspend_process(args)
    elif args.command == "resume":
        resume_process(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
