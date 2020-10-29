# US Air Force Academy Collegiate Penetration Testing Competition Packet

## Google Drive Structure

Folder for each team member with `logs` folder that logs should be copied to at end and running `notes` document.

Folder `scans` with document for each pasted nmap scan.

## VDI Setup

### Windows VDI

Recommended software to install:

- Bitvise SSH client - https://bitvise.com/ssh-client-download
- Wireshark -  https://www.wireshark.org/download.html 

### Linux VDI

Use Bitvise from Windows VDI to SSH to Linux VDI. On first login, in home folder, do this:

```sh
mkdir logs
echo "script ~/logs/\$(date +%s).log" >> .bash_profile
```

## Scripts

### Scanning Check

Add as `~/scan_check.sh`:

```sh
nmap <ip_range> -T4 -F -oN ~/new_scan
DIFF=$(diff ~/last_scan ~/new_scan)
if [ "$DIFF" != "" ]
then
	echo "$DIFF" > "diff-$(date +%s).txt"
	echo "Scan change at $(date +%s)" | wall
fi
rm ~/last_scan
mv ~/new_scan ~/last_scan
```

Add with `sudo crontab -e`:

```sh
*/15 * * * * sh /home/???/scan_check.sh
```

### Password List

Add as `old.txt`:

```
august2019
august19
september2019
september19
october2019
october19
november2019
november19
spring2019
spring19
winter2019
winter19
fall2019
fall19
bank
dino
dinobank
dinoBank
gotham
metropolis
springfield
```

Add as `combine.py`:

```python
def leet(strings, old, new):
    for x in strings:
        if old in x:
            strings.append(x.replace(old, new))

# Read the old passwords
with open("old.txt", "r") as f:
    old_list = f.read().split("\n")

# Add capitals
for x in old_list:
    old_list.append(x.capitalize())
    
# Add leetspeak
leet(old_list, "a", "@")
leet(old_list, "i", "1")
leet(old_list, "o", "0")
leet(old_list, "s", "5")

# Combine the strings
new_list = []
for x in old_list:
    for y in old_list:
        if x != y:
            new_list.append(x + y + "\n")
            
# Add the single word passwords
new_list.extend(old_list)

# Add 1 to end
for x in new_list:
    if not x[-1].isdigit():
        new_list.append(x + "1")
        
# Add ! to end
for x in new_list:
    new_list.append(x + "!")

# Write the new passwords
with open("new.txt", "w") as f:
    for x in new_list:
        f.write(x + "\n")
```

Put `new.txt` in the Google Drive.

## Reconnaissance

Initial scan (paste in a Google Doc):

```sh
nmap <ip_range> -T4 -F -oN scan_short
```

Much longer scan (paste in a Google Doc):

```sh
nmap <ip_range> -T4 -p- -A -oN scan_long
```

Dump traffic (use Bitvise on Windows to retrieve the PCAP and open it in Wireshark):

```sh
ifconfig # find name of interface
tcpdump -i <interface> -s 65535 -w dump.pcap
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

### GitHubs

https://github.com/DinoDanOliver/bluekeep-exploit
https://github.com/dino-alex-faulkner/dino -- what EVERYONE uses as a chat app
https://github.com/Dino-Bank/HelloWorld
https://github.com/DinoDanOliver/.files/
https://etherscan.io/address/0xfd77ee88f5678553a575b7302c48e9aba9597d8c#code - smart contract, shortens to https://bit.ly/2M34TaT

Private SSH key: https://bit.ly/2VvkiUB

## Regulations

As a leading financial institution, DinoBank has many regulations and frameworks it must maintain compliance with. These include: GLBA, PCI, FinCEN, KYC/AML, The US PATRIOT Act, FINRA, and others. 

GDPR - GENERAL DATA PROTECTION REGULATION

https://gdpr-info.eu/ (Official text)

https://digitalguardian.com/blog/what-gdpr-general-data-protection-regulation-understanding-and-complying-gdpr-data-protection (Important articles)

Any company that markets goods or services to EU residents, regardless of its location, is subject to the regulation

“DinoBank is international, there are foreign employees as well as customers in the foreign locations” 

Penalties: For companies that fail to comply with certain GDPR requirements, fines may be up to 2% or 4% of total global annual turnover or €10m or €20m, whichever is greater

GLBA - GRAMM-LEACH-BLILEY ACT

https://digitalguardian.com/blog/what-glba-compliance-understanding-data-protection-requirements-gramm-leach-bliley-act 

The GLBA requires that financial institutions act to ensure the confidentiality and security of customers’ “nonpublic personal information,” or NPI. Nonpublic personal information includes Social Security numbers, credit and income histories, credit and bank card account numbers, phone numbers, addresses, names, and any other personal customer information received by a financial institution that is not public. 

Financial institutions found in violation face fines of $100,000 for each violation.

PCI - PAYMENT CARD INDUSTRY DATA SECURITY STANDARD

https://www.tripwire.com/state-of-security/regulatory-compliance/beginners-guide-pci-compliance/

https://www.varonis.com/blog/pci-compliance/

If your organization processes, stores or transmits credit card data, you’re required to be PCI DSS compliant.

Level 1: Any merchant processing 6 million+ transactions per year across all channels or any merchant that has had a data breach. Credit card companies can also upgrade any merchant to Level 1 at their discretion.

Level 2: Any merchant processing between 1-6 million transactions per year across all channels.

Level 3: Any merchant processing between 20,000 and 1 million e-commerce transactions per year.

Level 4: Any merchant processing less than 20,000 e-commerce transactions per year or any merchant processing up to 1 million regular transactions per year.

Fines vary from $5,000 to $100,000 per month until the merchants achieve compliance.

Fines issued by the PCI are small in comparison to credit monitoring fees, laws suits, and actions by state and federal governments that can result when you’re not truly PCI DSS compliant.

KYC (KNOW YOUR CUSTOMER)/ AML (ANTI-MONEY LAUNDERING)

FinCEN - FINANCIAL CRIMES ENFORCEMENT NETWORK/PATRIOT ACT

https://www.investopedia.com/terms/f/fincen.asp

https://www.investopedia.com/terms/p/patriotact.asp

Government bureau that maintains a network whose goal it is to prevent and punish criminals and criminal networks that participate in money laundering and other financial crimes.

FinCEN is authorized to exercise regulatory duties per the Currency and Financial Transactions Reporting Act of 1970, as amended by Title III of the USA PATRIOT Act of 2001.

PATRIOT ACT

It [Patriot Act] also impacts the broader U.S. community of financial professionals and financial institutions engaging in cross-border transactions with its Title III provision, "International Money Laundering Abatement and Financial Anti-Terrorism Act of 2001.”

Title III - the practical result of the Patriot Act’s Title III provision effectively translates to unprecedented levels of due diligence on any corresponding accounts that exist in money-laundering jurisdictions throughout the world

## Other Teams

CalPoly has interesting setup scripts for Linux in `linux_setup`

RIT has service cheat sheets in `cheatsheet`

## External References

https://bit.ly/347bFTt - Windows AD pentesting guide

https://bit.ly/3117FS9 - various helpful red teaming resources

https://doc.lagout.org/ - various PDFs, including RTFM

https://bit.ly/2kSQao0 - various vulnerabilities, mostly web

https://lzone.de/cheat-sheet/ - various cheat sheets

https://devhints.io/ - more cheat sheets

https://devdocs.io/ - more detailed cheat sheets

https://www.robvanderwoude.com/ntadmincommands.php - commands for Windows admins