# Owlert

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

### ⚠️ Legal Notice
### Use Owlert **only** on networks you own or have explicit permission to test. <br>The author(s) take no responsibility for misuse.

#### Please report vulnerabilities via GitHub issues.

# 🦉 Owlert – Network Reconnaissance Toolkit

**Owlert** is a Python CLI that makes rapid port‑scanning and basic
service‑enumeration effortless across Class A (`/8`), Class B (`/16`),
and Class C (`/24`) IP ranges.

* AI Transparency at bottom.

| Core features             | Details                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| **Threaded port scans**   | • Quick scan (common ports) ←→ deep scan (1‑65535)  <br>• Adjustable /8 / /16 / /24 scope |
| **Single‑port discovery** | Target one port (e.g. SSH –22) across an entire subnet                                    |
| **Excel & CSV reports**   | Results auto‑exported (`quick_scan_results.xlsx`, `service_enum_results.xlsx`, …)         |
| **Banner enumeration**    | Simple banner grabs (HTTP, SSH, SSL/TLS cert CN, SMTP, FTP, generic)                      |

---
## 1 · Prerequisites

| Requirement | Version (tested) | Check command | Download |
|-------------|------------------|---------------|----------|
| **Python**  | 3.10 – 3.13      | `python --version` | [python.org/downloads](https://www.python.org/downloads/) |
| **pip**     | bundled with Python | `python -m pip --version` | *(installed automatically with Python 3.4+)* |

---
# Setup and Usage

## 2.  Virtual Environment Setup

Open Terminal (macOS / Linux) or PowerShell (Windows) in the folder that contains this **readme.md** 

then run the commands according to your platform.

### Windows PowerShell

```powershell
# 1. Create a virtual environment named ".venv"
python -m venv .venv

# 2. Activate the venv
.\.venv\Scripts\Activate.ps1
# (If you get an execution‑policy warning, run:
#    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process )

# 3. Install Owlert’s dependencies
python -m pip install -r requirements.txt

# 4. Launch Owlert
python -m OwlertV3.main

```

### macOS / Linux Terminal

```bash
# 1. Create a virtual environment named ".venv"
python3 -m venv .venv

# 2. Activate the venv
source .venv/bin/activate

# 3. Install Owlert’s dependencies
pip install -r requirements.txt

# 4. Launch Owlert
python -m OwlertV3.main

```

---

# Using the Program

### Primary Menu

📡 Owlert Network Recon 📡

1. Host Subnet Discovery
2. Specific Port Host Discovery
3. Scan All Ports for Hosts (Incredibly Slow!)
4. Fast Subnet-Wide Scan (Common Ports Scan)
5. Service Enumeration
6. exit

	type 'help' at anytime for a list of additional commands
📡 Network Recon: "User Input Here"

#### 1. Host Subnet Discovery

* This program simply scans and discovers the users subnet and the operating system they are utilizing. 
#### 2. Specific Port Host Discovery

* This function will prompt the user to select a port to scan. 
	* If none is inserted it defaults to 80.
* The function will then prompt the user which IP address class they would like to scan.
	* The user can prompt both the simple numerical (24) or include the slash (/24)
	* Should something else be inserted function defaults to Class B (/16) subnet scan.
#### 3. Scan All Ports for Hosts (Incredibly Slow!)

* The function will then prompt the user which IP address class they would like to scan.
	* The user can prompt both the simple numerical (24) or include the slash (/24)
	* Should something else be inserted function defaults to Class B (/16) subnet scan.
	* It will scan **ALL** ports across all the IP's within its assigned scope. Hence it being slow. 
	* It is limited to 256 threads in the host pool and 256 threads in the port pool.
* It will output the results as an Excel (.xlsx) file titled "all_port_scan_results.xlsx" in the OwlertV3 folder. 
#### 4. Fast Subnet-Wide Scan (Common Ports Scan)

* The function will then prompt the user which IP address class they would like to scan.
	* The user can prompt both the simple numerical (24) or include the slash (/24)
	* Should something else be inserted function defaults to Class B (/16) subnet scan.
	* It will first scan common ports across all the IP's within its assigned scope. Hence it being the "fast" scanning option. If it does not find anything in these common ports, it moves on to the next host address. 
		* Should it find a host, it will then do a deep scan, checking all the ports of that host to see what others it might have open.
* It will output the results as an Excel (.xlsx) file titled "quick_scan_results.xlsx" in the OwlertV3 folder.  
#### 5. Service Enumeration

* This program will prompt the user whether they want to target a specific IP, use the default "quick_scan_results.xlsx" or type out the name of a .xlsx file of their choosing. 
	* Should the user wish to scan their own file, simply place it alongside the main.py file inside the OwlertV3 directory.
* This program will use the columns from the .xlsx file as a guide to scan the listed hosts and ports and attempt to enumerate them.
* Upon doing so it will generate file's titled "service_enum_results.xlsx" and "service_enum_results.csv" within the OwlertV3 directory. Which will list the enumerated service if possible. 
#### 6. Exit

* This simply exits or closes the program intentionally
* The user can additionally type "exit". 
---

COMMON_PORTS 
     21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,  
     143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 993, 995, 1080, 1194,  
     1433, 1434, 1521, 1723, 2049, 2121, 3306, 3389, 3690, 4444, 5060, 5432,  
     5900, 5985, 5986, 6379, 8080, 8443, 8888, 9000, 9090, 9200, 27017  


### Help Menu

 🦉 Owlert Global Commands 🦉

Remember you can all upon these at any time!

```
>    [help]     > brings up Global Commands Menu 
>    [clear]    > wipes the terminal screen
>    [home]     > Bring up the home menu
>    [version]  > Bring up the current program version number
>    [exit]     > exit the program
```

---
#### AI Transparency

Parts of Owlert’s code were generated with OpenAI’s ChatGPT (GPT‑4o) and then
manually reviewed, tested, and refined.

