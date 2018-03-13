# cuttlefish

**cuttlefish** has morphed from my original intention of a host-distributed webapp enumeration tool, into an automated scanning tool for single-host penetration testing. I am going to enroll in OffSec's PWK to prepare for taking the OSCP, and want to have a tool that will help me perform automated host enumeration. Additionally, I wanted to learn `go` from a practical project PoV.

![cuttle-demo](img/cuttle-demo.gif)

### installation

An automated install script has been setup for linux (only tested on 64-bit Kali)

```
./linux_install.sh
```

If you would like to install on a mac, install `go`, and perform the steps from the install script (post golang-installation) one at a time.

### usage

```
$ ./cuttlefish -h
Usage of ./cuttlefish:
  -d int
    	depth of initial scan. 1(light) -> 3(heavy) (default 1)
  -f string
    	run secondary scans from nmap output file (non-greppable format) (default "d34db33f")
  -i string
    	Interface to scan on (eth0)
  -l string
    	location of output log file
  -s string
    	Type of scan to use for initial recon (nmap | unicorn) [default nmap] (default "nmap")
  -t string
    	IP address of target machine (default "d34db33f")
  -testing
    	use test executables for enum output
  -u	perform recon UDP scan
```

### example enumeration

```
$./cuttlefish -target=127.0.0.1 -testing=true
$-------------.__   ,+-.           ,+ ~.     ,-----------
           O  o `- o ,-`           `.o `._./            
o   O   o   o _O  o /   cuttlefish   \ O  o    O   o   O
__o___O____,-`  `\_*         v0.0     \._____o___coastal
[~] supports identification and enumeration of: 
	ftp, ssh, telnet, smtp, snmp, ftp, http, https
	smb, ms-sql, rdp
[*] running in test mode
[*] run options
	[*] logging to /Users/coastal/Documents/oscp/labs
	[*] target:		127.0.0.1
[!] not executed as root (GUID: 501), script scanning not performed
[*] starting intial nmap recon scan
	[+] scan: nmap-tcp-recon	[port:all]	(complete)	[time elapsed: 0.91s]
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
	[!] scan: telnet-banner		[port:23]	(error)		[time elapsed: 0.00s]
	[!] scan: smtp-user-enum	[port:25]	(error)		[time elapsed: 0.06s]
	[!] scan: http-curl-scan	[port:80]	(error)		[time elapsed: 0.00s]
	[!] scan: robots-txt-scan	[port:80]	(error)		[time elapsed: 0.00s]
	[+] scan: ftp-nmap-scan		[port:21]	(complete)	[time elapsed: 0.96s]
	[+] scan: smtp-nmap-enum	[port:25]	(complete)	[time elapsed: 0.96s]
	[+] scan: http-nmap-scan	[port:80]	(complete)	[time elapsed: 0.96s]
	[+] scan: smb-nmap-vuln		[port:445]	(complete)	[time elapsed: 0.96s]
	[+] scan: smb-nmap-enum		[port:445]	(complete)	[time elapsed: 0.96s]
	[+] scan: gobuster-dir-enum	[port:80]	(complete)	[time elapsed: 1.99s]
	[+] scan: gobuster-cgi-enum	[port:80]	(complete)	[time elapsed: 1.99s]
	[+] scan: smb-enumlinux-scan	[port:445]	(complete)	[time elapsed: 3.01s]
	[+] scan: nikto-scan		[port:80]	(complete)	[time elapsed: 4.02s]
	[+] scan: hydra-ftp-brute	[port:21]	(complete)	[time elapsed: 9.90s]
	[+] scan: hydra-ssh-brute	[port:22]	(complete)	[time elapsed: 10.01s]
	[+] scan: hydra-rdp-brute	[port:3389]	(complete)	[time elapsed: 10.01s]
[+] cuttlefish enumeration of 127.0.0.1 complete! (0.19 mins)[0m
```

### example log files

```
$ tree ~/Documents/oscp/labs
└── 127.0.0.1-cuttlefish-enum
    └── 2018-01-25T23:23:27-05:00
        ├── 127.0.0.1-cuttlemain.cuttlelog
        ├── 127.0.0.1-port21-ftp-nmap-scan.cuttlelog
        ├── 127.0.0.1-port21-hydra-ftp-brute.cuttlelog
        ├── 127.0.0.1-port22-hydra-ssh-brute.cuttlelog
        ├── 127.0.0.1-port23-telnet-banner.cuttlelog
        ├── 127.0.0.1-port25-smtp-nmap-enum.cuttlelog
        ├── 127.0.0.1-port25-smtp-user-enum.cuttlelog
        ├── 127.0.0.1-port3389-hydra-rdp-brute.cuttlelog
        ├── 127.0.0.1-port445-smb-enumlinux-scan.cuttlelog
        ├── 127.0.0.1-port445-smb-nmap-enum.cuttlelog
        ├── 127.0.0.1-port445-smb-nmap-vuln.cuttlelog
        ├── 127.0.0.1-port80-gobuster-cgi-enum.cuttlelog
        ├── 127.0.0.1-port80-gobuster-dir-enum.cuttlelog
        ├── 127.0.0.1-port80-http-curl-scan.cuttlelog
        ├── 127.0.0.1-port80-http-nmap-scan.cuttlelog
        ├── 127.0.0.1-port80-nikto-scan.cuttlelog
        ├── 127.0.0.1-port80-robots-txt-scan.cuttlelog
        └── 127.0.0.1-portall-nmap-tcp-recon.cuttlelog
```
