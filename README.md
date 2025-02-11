<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/GGCasual/Threat-Hunting-Tor-Scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario 

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-02-09T02:57:47.5069816Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-09T02:57:47.5069816Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src=Pictures\image-1.png>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcesEvents` table for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.0.6.exe`. Based on the logs returned, at `2025-02-09T03:07:26.1525083Z`, an employee on the “threat-hunt-lab” device ran the file `tor-browser-windows-x86_64-portable-14.0.6.exe` from their Downloads using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src=Pictures\image-2.png>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table to indicate that the user “employee” opened the Tor browser. There was evidence that they did open at `2025-02-09T03:07:58.083085Z`, along with several other instances of `firefox.exe` (Tor) and `tor.exe` spawned afterward. 

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src=Pictures\image-1.png>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication that the Tor browser was used to establish a connection using any known Tor ports. On `2025-02-09T03:08:17.750641Z`, an action was logged from a device named "threat-hunt-lab." The action was initiated by an account called "employee," it was a successful connection attempt. The connection was made to the remote IP address `192.42.116.203` on port `9001`, using the URL `https://www.tsrjhoy3ntdjeu4vfzv.com.` The process initiating the connection was "tor.exe," located in the folder path `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe.` This suggests the Tor browser was used to connect to a potentially suspicious remote server. Some connections were made using other port `443` well.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src=Pictures\image-3.png>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-09T02:57:47.5069816Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-09T03:07:26.1525083Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-09T03:07:58.083085Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-02-09T03:08:17.750641Z`
- **Event:** A network connection to IP `192.42.116.203` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-09T03:08:12.4583622Z` - Connected to `147.135.54.178` on port `443`.
  - `2025-02-09T03:08:32.5940097Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-09T03:30:32.8670034Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
