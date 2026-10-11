### **System Process Manager**

A Command-Line Interface (CLI) utility built in Python to monitor, manage, and interact with operating system processes in real-time. This tool utilizes Python's system-level libraries to handle resource allocation and process lifecycle management safely and efficiently.

**Features**

Live Process Monitoring: View a tabular list of active processes including PID, Name, Path/Command Line, CPU usage (%), and Memory consumption (MB).

Advanced Sorting: Sort the active processes by CPU, Memory, or PID in ascending or descending order.

Asynchronous Execution: Launch new programs in the background (non-blocking) with optional command-line arguments and custom working directories.

Graceful Termination: Safely stop processes by attempting a graceful terminate first, falling back to a force-kill if the process does not respond within a timeout window.

Process State Management: Suspend (pause) and resume processes, complete with state validation to prevent redundant system calls.

Prerequisites

Python 3.x

psutil library

To install the required library, run:
pip install psutil

Usage

The application uses subcommands to handle different functionalities. Use -h or --help after any command to see detailed usage instructions.

**1. View Processes (Live Metrics & Sorting)**

Display all running processes. By default, it sorts by PID.
python process.py view

Sorting Options: You can sort the output by cpu, mem, or pid, and use the -desc flag for descending order.
python process.py view -sort cpu -desc
python process.py view -sort mem -desc

**2. Start a Process**

Launch a new application in the background. It returns the new process PID.
python process.py run <path_to_executable> [optional_arguments]

Example (Windows):
python process.py run ping.exe localhost -t

Optional: Specify a working directory using -cwd.
python process.py run cmd.exe -cwd "C:\Users\Public"

**3. Terminate a Process**

Stop a process using its PID. The script will try to terminate it gracefully (waiting up to 3 seconds) before forcing a kill.
python process.py kill <PID>

**4. Suspend a Process**

Pause a running process.
python process.py suspend <PID>

**5. Resume a Process**

Resume a previously suspended process.
python process.py resume <PID>

Error Handling

The tool includes robust error handling for common system-level issues:

Access Denied: Alerts the user when Administrator privileges are required to interact with specific system processes.

Process Not Found: Validates if a PID exists before attempting lifecycle changes.

State Validation: Prevents attempting to suspend an already suspended process (or resume a running one).
