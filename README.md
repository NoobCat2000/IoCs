# Windows Event IDs – Threat Hunting Reference

> Chỉ liệt kê các Event ID có giá trị cho **Threat Hunting** (bỏ qua event thông thường/noise).  
> Splunk queries tương ứng nằm trong các file `.spl` cùng thư mục.

---

## Mục lục
1. [Security Log (Channel: Security)](#1-security-log)
2. [System Log (Channel: System)](#2-system-log)
3. [PowerShell Logs](#3-powershell-logs)
4. [Sysmon (Microsoft-Windows-Sysmon/Operational)](#4-sysmon)
5. [IIS Logs](#5-iis-logs)
6. [Windows Defender](#6-windows-defender)
7. [Task Scheduler](#7-task-scheduler)
8. [Bảng tra nhanh: MITRE ATT&CK ↔ Event ID](#8-bảng-tra-nhanh-mitre-attck--event-id)

---

## 1. Security Log

> **Channel:** `Security` | **Splunk source:** `WinEventLog:Security`  
> Bật qua: Group Policy → Advanced Audit Policy Configuration

### Logon / Authentication

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **4624** | Successful Logon | Lọc `LogonType=3` (network) hoặc `LogonType=10` (RDP) ngoài giờ hành chính; tài khoản service logon bất thường |
| **4625** | Failed Logon | > 5 lần/phút → brute force; `LogonType=3` từ nhiều IP → password spray |
| **4648** | Logon with Explicit Credentials | Dấu hiệu `runas`, pass-the-hash, lateral movement; `SubjectUserName` ≠ `TargetUserName` |
| **4672** | Special Privileges Assigned | Theo dõi tài khoản không phải Domain Admin nhận `SeDebugPrivilege` hoặc `SeImpersonatePrivilege` |
| **4768** | Kerberos TGT Request | `EncryptionType=0x17` (RC4) → Kerberoasting hoặc hệ thống cũ không dùng AES |
| **4769** | Kerberos Service Ticket Request | `TicketEncryptionType=0x17` + service account → Kerberoasting; nhiều request từ 1 user → enumeration |
| **4771** | Kerberos Pre-Auth Failed | Tương tự 4625 cho Kerberos; `0x18` = sai password |
| **4776** | NTLM Auth Attempt | Workstation dùng NTLM thay Kerberos → lateral movement hoặc pass-the-hash |
| **4778** | RDP Session Reconnected | Theo dõi ai reconnect; chuỗi `4778→4624` từ IP lạ |
| **4779** | RDP Session Disconnected | Kết hợp với 4778 để track toàn bộ RDP session |

**LogonType quan trọng:**
```
2  = Interactive (local console)     9  = NewCredentials (runas /netonly)
3  = Network (SMB, WMI, net use)    10  = RemoteInteractive (RDP)
4  = Batch (scheduled task)         11  = CachedInteractive (offline domain)
5  = Service                         7  = Unlock (screensaver)
```

### Quản lý tài khoản

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **4720** | User Account Created | Tài khoản mới tạo ngoài quy trình HR → backdoor account |
| **4722** | User Account Enabled | Kích hoạt lại tài khoản bị disable → persistence |
| **4724** | Password Reset | Admin reset password tài khoản khác ngoài helpdesk ticket → privilege abuse |
| **4725** | User Account Disabled | Attacker vô hiệu hóa tài khoản để gây gián đoạn |
| **4728** | Member Added to Global Group | Thêm vào `Domain Admins`, `Enterprise Admins` |
| **4732** | Member Added to Local Group | Thêm vào local `Administrators` → privilege escalation |
| **4738** | User Account Changed | Thay thuộc tính tài khoản (ví dụ: bỏ "Password must change") |
| **4740** | User Account Locked Out | Brute force hoặc password spray đang diễn ra |
| **4798** | Local Group Membership Enumerated | Recon: công cụ đang query thành viên local group |
| **4799** | Security-Enabled Local Group Queried | Thường đi kèm 4798 |

### Process & Object Access

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **4656** | Object Handle Requested | `ObjectName=lsass.exe` → credential dumping attempt |
| **4657** | Registry Value Modified | Theo dõi key autorun, `HKLM\SAM`, `HKLM\SECURITY` |
| **4663** | Object Access | Đọc `ntds.dit`, `SAM`, `SYSTEM` hive → credential dumping |
| **4688** | Process Created | **Quan trọng nhất** – cần bật "Include command line"; `cmd.exe`/`powershell.exe` spawn từ Office/browser |
| **4697** | Service Installed | Service mới → persistence hoặc lateral movement (PsExec tạo service) |
| **4698** | Scheduled Task Created | Persistence phổ biến; `TaskContent` chứa path trong `%TEMP%`, `AppData` |
| **4702** | Scheduled Task Updated | Attacker sửa task sẵn có → ít bị phát hiện hơn tạo mới |
| **4719** | Audit Policy Changed | Attacker tắt logging để xóa dấu vết |

### Network

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **5140** | Network Share Accessed | `ShareName=C$` hoặc `ADMIN$` từ IP lạ → lateral movement |
| **5145** | Network Share Object Access | Granular hơn 5140; `IPC$` → SMB enumeration |
| **5156** | WFP Connection Permitted | Kết nối ra cổng lạ từ process hợp lệ (`svchost`, `explorer`) → C2 |
| **5157** | WFP Connection Blocked | Nhiều event từ 1 source trong thời gian ngắn → port scan |

---

## 2. System Log

> **Channel:** `System` | **Splunk source:** `WinEventLog:System`

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **7034** | Service Crashed Unexpectedly | Payload không ổn định crash liên tục |
| **7036** | Service Started/Stopped | Dịch vụ lạ khởi động; Windows Defender bị tắt |
| **7040** | Service Start Type Changed | Từ `SYSTEM` → `Disabled` → attacker tắt AV/EDR |
| **7045** | New Service Installed | **Rất quan trọng** – PsExec, Cobalt Strike service; `ServiceFileName` trỏ tới `%TEMP%`, `AppData` |

---

## 3. PowerShell Logs

> Cần bật trong Group Policy:  
> - `Module Logging` → ghi output lệnh  
> - `Script Block Logging` → ghi toàn bộ script (kể cả sau deobfuscation)

### Windows PowerShell (Classic)
**Channel:** `Windows PowerShell`

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **400** | Engine Started | `HostApplication` chứa `-enc`, `-e`, `-EncodedCommand` → obfuscated payload |
| **600** | Provider Started | Provider `WSMan` bất ngờ → PowerShell remoting |

### PowerShell Operational
**Channel:** `Microsoft-Windows-PowerShell/Operational`

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **4103** | Module Logging | Ghi output từng lệnh; tìm `Invoke-Mimikatz`, `Invoke-Empire`, `Get-Credential`, `net user` |
| **4104** | Script Block Logging | **Quan trọng nhất** – ghi toàn bộ script sau deobfuscation; tìm `IEX`, `DownloadString`, `FromBase64String`, `Reflection.Assembly::Load` |
| **4105** | Script Block Started | Thời điểm bắt đầu thực thi script |
| **4106** | Script Block Completed | Thời điểm kết thúc |

**Splunk – Phát hiện PowerShell download cradle:**
```splunk
source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
(ScriptBlockText="*DownloadString*" OR ScriptBlockText="*WebClient*"
 OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*"
 OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*Net.WebRequest*")
| table _time, Computer, ScriptBlockText
```

---

## 4. Sysmon

> **Channel:** `Microsoft-Windows-Sysmon/Operational`  
> **Splunk source:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`  
> Config khuyên dùng: [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) hoặc [Olaf Hartong](https://github.com/olafhartong/sysmon-modular)

| EID | Tên sự kiện | Mục đích Threat Hunting | Trường quan trọng |
|-----|-------------|------------------------|-------------------|
| **1** | Process Creation | Thay thế EID 4688, chi tiết hơn (hash, parent CLI) | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes`, `User` |
| **2** | File Creation Time Changed | **Timestomping** – attacker sửa timestamp file để ẩn | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` |
| **3** | Network Connection | Outbound từ `powershell.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe` → C2 | `Image`, `DestinationIp`, `DestinationPort`, `Initiated` |
| **5** | Process Terminated | Process tồn tại rất ngắn (< 1s) → defense evasion | `Image`, `ProcessGuid` |
| **6** | Driver Loaded | Driver không có chữ ký số hợp lệ → **BYOVD** attack | `ImageLoaded`, `Signed`, `Signature`, `Hashes` |
| **7** | Image Loaded (DLL) | DLL injection; DLL lạ load vào `lsass.exe`, `explorer.exe`, `svchost.exe` | `Image`, `ImageLoaded`, `Signed`, `SignatureStatus` |
| **8** | CreateRemoteThread | **Dấu hiệu injection rõ nhất** – Cobalt Strike, Metasploit, shellcode injection | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule` |
| **9** | RawAccessRead | Đọc trực tiếp disk bypassing filesystem → credential dumping (`\Device\HarddiskVolume`) | `Image`, `Device` |
| **10** | ProcessAccess | `lsass.exe` bị đọc memory → **Mimikatz**, credential dumping | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` |
| **11** | File Created | Drop file vào `%TEMP%`, `AppData`, Startup folder; payload stage 2 | `TargetFilename`, `Image`, `CreationUtcTime` |
| **12** | Registry Object Added/Deleted | Persistence qua registry; xóa key để xóa dấu vết | `EventType`, `TargetObject` |
| **13** | Registry Value Set | Autorun keys, thay đổi security settings, disable defender | `TargetObject`, `Details` |
| **14** | Registry Key/Value Renamed | Đổi tên key để ẩn persistence | `TargetObject`, `NewName` |
| **15** | File Stream Created (ADS) | **Alternate Data Stream** – ẩn executable trong NTFS stream | `TargetFilename`, `Contents` |
| **17** | Named Pipe Created | Pipe của Cobalt Strike (`\\.\pipe\msagent_*`), PsExec | `PipeName`, `Image` |
| **18** | Named Pipe Connected | Kết nối tới named pipe → lateral movement qua SMB | `PipeName`, `Image` |
| **19** | WMI Event Filter Registered | **WMI persistence** bước 1 – đăng ký điều kiện trigger | `Name`, `Query` |
| **20** | WMI Event Consumer Registered | **WMI persistence** bước 2 – đăng ký hành động thực thi | `Name`, `Type`, `Destination` |
| **21** | WMI Consumer Bound to Filter | **WMI persistence** bước 3 – hoàn chỉnh chuỗi persistence | `Consumer`, `Filter` |
| **22** | DNS Query | Domain mới lạ, DGA pattern, DNS tunneling; query từ non-browser process | `Image`, `QueryName`, `QueryResults` |
| **23** | File Deleted | Attacker xóa tool/payload sau khi dùng; theo dõi xóa `.exe`, `.ps1`, `.bat` từ temp | `TargetFilename`, `Image`, `Hashes` |
| **25** | Process Tampering | **Process hollowing**, process herpaderping | `Image`, `Type` |
| **26** | File Delete Logged | Sysmon archive file bị xóa (nếu bật ArchiveDirectory) | `TargetFilename` |

**Splunk – LSASS access (credential dumping):**
```splunk
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
NOT SourceImage IN ("*\\MsMpEng.exe","*\\csrss.exe","*\\wininit.exe",
                    "*\\svchost.exe","*\\WerFault.exe","*\\taskmgr.exe")
| table _time, Computer, SourceImage, GrantedAccess, CallTrace
```

**Splunk – WMI persistence (phải có đủ cả 3 EID):**
```splunk
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19, 20, 21)
| table _time, Computer, EventCode, Name, Type, Destination, Query
| sort _time
```

**Splunk – Phát hiện process injection qua CreateRemoteThread:**
```splunk
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
NOT (SourceImage IN ("*\\svchost.exe","*\\csrss.exe","*\\wininit.exe")
     AND TargetImage IN ("*\\svchost.exe"))
| table _time, Computer, SourceImage, TargetImage, StartAddress, StartModule
```

---

## 5. IIS Logs

> **Không phải Windows Event Log** – IIS ghi file W3C text tại:  
> `C:\inetpub\logs\LogFiles\W3SVC<SiteID>\u_ex<YYYYMMDD>.log`  
> **Splunk:** cấu hình `[monitor://C:\inetpub\logs\...]` với `sourcetype = iis`

### Các trường W3C cần quan tâm

| Trường | Mô tả | Threat Hunting |
|--------|-------|----------------|
| `c-ip` | Client IP | IP từ Tor, hosting/VPS, hoặc IP lạ chưa từng xuất hiện |
| `cs-method` | HTTP Method | `PUT`, `DELETE`, `TRACE`, `CONNECT`, `OPTIONS` bất thường |
| `cs-uri-stem` | URL path | Chứa `../`, `%2e%2e`, `.php` trên IIS, `/cmd`, `/shell`, `/.git` |
| `cs-uri-query` | Query string | SQL injection: `' OR 1=1`, `UNION SELECT`; XSS: `<script>`, `onerror=` |
| `sc-status` | HTTP Status code | Nhiều 404 → scanning; 500 → exploitation; 200 ngay sau 404 → found shell |
| `sc-bytes` | Response bytes | Response lớn sau POST ngắn → data exfiltration |
| `cs(User-Agent)` | User-Agent | `sqlmap`, `nikto`, `nmap`, `python-requests`, empty, hoặc chuỗi lạ |
| `cs-username` | Auth username | Failed auth attempts trên Basic/NTLM auth |
| `time-taken` | Response time (ms) | Spike đột ngột → heavy SQL injection query |

**Splunk – Web shell & injection detection:**
```splunk
index=iis sc_status=200
(match(cs_uri_stem,"(?i)(cmd|shell|webshell|upload|eval|c99|r57)")
 OR match(cs_uri_query,"(?i)(select|union|exec|xp_cmd|' or |1=1|;drop)")
 OR match(cs_uri_query,"(?i)(<script|javascript:|onerror=|onload=)")
 OR match(cs_uri_stem,"\.\./")
 OR cs_method IN ("PUT","DELETE","TRACE","CONNECT"))
| table _time, c_ip, cs_method, cs_uri_stem, cs_uri_query, sc_status, cs_useragent
```

**Splunk – Web shell: POST tới script file trả 200:**
```splunk
index=iis sc_status=200 cs_method=POST
(cs_uri_stem="*.asp" OR cs_uri_stem="*.aspx"
 OR cs_uri_stem="*.php" OR cs_uri_stem="*.jsp")
| stats count, values(c_ip) as src_ips, values(cs_useragent) as agents
      by cs_uri_stem
| where count > 3
| sort -count
```

**Splunk – Scanning detection (nhiều 404 từ 1 IP):**
```splunk
index=iis sc_status=404
| bin _time span=1m
| stats count by _time, c_ip
| where count > 30
| sort -count
```

**Splunk – Exfiltration qua large response:**
```splunk
index=iis cs_method=POST sc_status=200
| eval mb = sc_bytes / 1024 / 1024
| where mb > 10
| table _time, c_ip, cs_uri_stem, mb, cs_useragent
| sort -mb
```

---

## 6. Windows Defender

> **Channel:** `Microsoft-Windows-Windows Defender/Operational`

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **1116** | Malware Detected | Tên malware, path, user; nhiều detection cùng lúc → outbreak đang lây lan |
| **1117** | Action Taken on Malware | `Action=Failed` → malware vẫn còn tồn tại trên máy |
| **1121** | AMSI Detection (Block) | Script/command bị chặn qua AMSI; `Path` chứa `lsass` → credential dumping bị chặn |
| **5001** | Real-time Protection Disabled | **Alert ngay** – attacker hoặc GPO lạ tắt AV |
| **5007** | Config Changed | Exclusion path bị thêm vào → attacker tạo blind spot để bypass |
| **5010** | Scanning for Malware Disabled | |
| **5101** | Platform Update Failed | Bản cập nhật signature bị chặn → máy dùng signature cũ |

---

## 7. Task Scheduler

> **Channel:** `Microsoft-Windows-TaskScheduler/Operational`

| Event ID | Tên | Threat Hunting |
|----------|-----|----------------|
| **106** | Task Registered | Task mới được tạo; kiểm tra `TaskName` và `UserContext` |
| **129** | Task Launched | `Path` trỏ tới `%TEMP%`, `AppData`, `Downloads` → persistence payload |
| **141** | Task Deleted | Attacker xóa task sau khi dùng để xóa dấu vết |
| **200** | Task Action Started | Lệnh thực sự được thực thi |
| **201** | Task Action Completed | Ghi nhận kết quả và thời gian chạy |

---

## 8. Bảng tra nhanh: MITRE ATT&CK ↔ Event ID

| Kỹ thuật tấn công | MITRE | Event ID cần xem |
|-------------------|-------|------------------|
| Credential Dumping – LSASS | T1003.001 | Sysmon 10, Security 4656 |
| Credential Dumping – NTDS | T1003.003 | Security 4663 (`ntds.dit`), Sysmon 9 |
| Pass-the-Hash | T1550.002 | Security 4624 (LogonType=3, NTLM) |
| Pass-the-Ticket | T1550.003 | Security 4768/4769 |
| Kerberoasting | T1558.003 | Security 4769 (RC4/EncType=0x17) |
| Process Injection | T1055 | Sysmon 8, 10 |
| Process Hollowing | T1055.012 | Sysmon 25, 1 |
| PowerShell Execution | T1059.001 | PS 4104, Sysmon 1 |
| WMI Persistence | T1546.003 | Sysmon 19/20/21 |
| Scheduled Task | T1053.005 | Security 4698/4702, TaskScheduler 106/129 |
| Service Persistence | T1543.003 | System 7045, Security 4697 |
| Registry Autorun | T1547.001 | Sysmon 12/13, Security 4657 |
| Timestomping | T1070.006 | Sysmon 2 |
| Alternate Data Stream | T1564.004 | Sysmon 15 |
| BYOVD (Driver) | T1068 | Sysmon 6 |
| Lateral Movement – SMB/PsExec | T1021.002 | Security 4624(L3)+5140, System 7045 |
| Lateral Movement – WMI | T1021.003 | Security 4688, Sysmon 1+3 |
| Lateral Movement – RDP | T1021.001 | Security 4778, 4624(L10) |
| C2 – DNS Tunneling | T1071.004 | Sysmon 22 |
| C2 – Web Shell | T1505.003 | IIS log (POST 200 tới .asp/.php) |
| Exfiltration via Web | T1041 | IIS log (POST large sc-bytes) |
| Brute Force | T1110 | Security 4625 (nhiều lần liên tiếp) |
| Password Spray | T1110.003 | Security 4625 (nhiều user, 1 IP) |
| Account Creation | T1136 | Security 4720 + 4728/4732 |
| Disable Security Tools | T1562.001 | Defender 5001/5007, System 7036/7040 |
| Clear Event Logs | T1070.001 | Security 1102, System 104 |
| Named Pipe – C2 | T1559.001 | Sysmon 17/18 |

---

## File SPL trong thư mục này

| File | Nội dung | Số rules |
|------|----------|----------|
| `windows_security_auth.spl` | Security log – auth, privilege, object access | 144 |
| `windows_process_creation.spl` | EID 4688 – process độc hại | 1114 |
| `windows_powershell.spl` | PowerShell attack detection | 208 |
| `windows_registry.spl` | Registry tampering & persistence | 237 |
| `windows_sysmon.spl` | Sysmon EID 1–29 | 2379 |
| `windows_network.spl` | WFP network filter (EID 5156) | 31 |
| `windows_windefend.spl` | Windows Defender alerts | 16 |
| `windows_taskscheduler.spl` | Task Scheduler abuse | 3 |
