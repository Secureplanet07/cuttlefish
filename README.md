# cuttlefish

**cuttlefish** has morphed from my original intention of a host-distributed webapp enumeration tool, into an automated scanning tool for single-host penetration testing. I am going to enroll in OffSec's PWK to prepare for taking the OSCP, and want to have a tool that will help me perform automated host enumeration. Additionally, I wanted to learn `go` from a practical project PoV.

### sample output

```
$ ./cuttlefish -target=192.168.56.3 -testing=true

-------------.__   ,+-.           ,+ ~.     ,-----------
           O  o `- o ,-`           `.o `._./            
o   O   o   o _O  o /   cuttlefish   \ O  o    O   o   O
__o___O____,-`  `\_*         v0.0     \._____o___coastal
[*] run options
	[*] logging to /Users/coastal/Downloads/192.168.56.3-cuttlefish-enum
	[*] target 192.168.56.3
	[*] aws tentacles 0
[!] not executed as root (GUID: 501), script scanning not performed
[*] starting intial nmap recon scan
        [+] scan: initial nmap TCP recon (complete) [time elapsed: 3.01s]       
[+] identified running services
	[+] ftp (21)
	[+] ssh (22)
	[+] telnet (23)
	[+] smtp (25)
	[+] domain (53)
	[+] http (80)
	[+] rpcbind (111)
	[+] netbios-ssn (139)
	[+] microsoft-ds (445)
	[+] exec (512)
	[+] login (513)
	[+] shell (514)
	[+] rmiregistry (1099)
	[+] ingreslock (1524)
	[+] nfs (2049)
	[+] ccproxy-ftp (2121)
	[+] mysql (3306)
	[-] ms-wbt-server (3389)
	[+] postgresql (5432)
	[+] vnc (5900)
	[+] X11 (6000)
	[+] irc (6667)
	[+] ajp13 (8009)
	[+] unknown (8180)
[*] starting follow up scans on identified services
        [+] scan: ssh hydra brute (complete) [time elapsed: 6.93s]              
        [+] scan: gobuster enumeration (complete) [time elapsed: 4.97s]         
[+] cuttlefish enumeration of 192.168.56.3 complete!
```