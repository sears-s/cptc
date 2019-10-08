# US Air Academy Collegiate Penetration Testing Competition Packet

## Google Drive Structure

`Deconfliction`

| Name  | IP Address | Type of Attack | Completed | Description |
| ----- | ---------- | -------------- | --------- | ----------- |
| Sears | 8.8.8.8    | Cyber Nuke     | Yes/No    | Example     |
| ...   | ...        | ...            | ...       | ...         |

`Persistence`

| Name  | Victim IP:Port | Callback IP:Port | Type         | Notes   | Location      |
| ----- | -------------- | ---------------- | ------------ | ------- | ------------- |
| Sears | 8.8.8.8:420    | 192.168.1.1:6969 | Reverse/Bind | Example | /tmp/hack.exe |
| ...   | ...            | ...              | ...          | ...     | ...           |

`[name] Notetaker`

```
IP:
User:
Type of Exploit: Initial / Privilege Escalation / Pivot / Information Disclosure etc.
Complete: Yes / No
Walkthrough: include commands, screenshots, other notes, etc.
```

## VDI Setup

### Windows VDI

1. Go to https://github.com/fireeye/commando-vm
2. Download and extract ZIP in Downloads
3. Download `profile.json` and `profile_full.json` from ??? to the same folder
4. Run this in PowerShell as admin:

```powershell
Set -ExecutionPolicy Unrestricted
A
cd ${Env:UserProfile}\Downloads\commando-vm-master\commando-vm-master\
.\install.ps1 -profile_file .\profile.json -password [windows_password]
R
Y
N
.\install.ps1 -profile_file .\profile_full.json # for more tools
```

### Linux VDI

In a terminal:

```bash
sudo su - # makes you root
apt-get install git
git clone https://github.com/1N3/Sn1per.git
cd Sn1per
sh install_debian_ubuntu.sh # there will be a couple prompts after
```

## External References

https://lzone.de/cheat-sheet/

https://devhints.io/

https://devdocs.io/