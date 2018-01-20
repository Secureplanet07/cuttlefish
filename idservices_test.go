package main

import (
	"testing"
)

var nmap_output_1 = `
Starting Nmap 7.60 ( https://nmap.org ) at 2018-01-01 22:26 EST
Nmap scan report for 10.10.10.27
Host is up (0.11s latency).
Not shown: 1998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:46:31:9c:b5:71:c5:96:91:7d:e4:63:16:f9:59:a2 (RSA)
|   256 10:c4:09:b9:48:f1:8c:45:26:ca:f6:e1:c2:dc:36:b9 (ECDSA)
|_  256 a8:bf:dd:c0:71:36:a8:2a:1b:ea:3f:ef:66:99:39:75 (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Brotherhood Software
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=1/1%OT=22%CT=1%CU=42975%PV=Y%DS=2%DC=T%G=Y%TM=5A4AFC11
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=106%GCD=1%ISR=10A%TI=Z%II=I%TS=8)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%lRID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   136.76 ms 10.10.14.1
2   117.84 ms 10.10.10.27
`
var nmap_output_2 = `
Nmap scan report for 192.168.56.3
Host is up (0.0074s latency).
Not shown: 976 filtered ports
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
23/tcp   open   telnet
25/tcp   open   smtp
53/tcp   open   domain
80/tcp   open   http
111/tcp  open   rpcbind
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
512/tcp  open   exec
513/tcp  open   login
514/tcp  open   shell
1099/tcp open   rmiregistry
1524/tcp open   ingreslock
2049/tcp open   nfs
2121/tcp open   ccproxy-ftp
3306/tcp open   mysql
3389/tcp closed ms-wbt-server
5432/tcp open   postgresql
5900/tcp open   vnc
6000/tcp open   X11
6667/tcp open   irc
8009/tcp open   ajp13
8180/tcp open   unknown
`

func TestIdentifyServices1(t *testing.T) {
	identified := identifyServices(nmap_output_1)
	if len(identified) != 2 {
		t.Errorf("did not ID ssh and http\n")
	}
	if identified[0].name != "ssh" && identified[0].port != "22" {
		t.Errorf("did not properly ID ssh\n")
	}
	if identified[1].name != "http" && identified[1].port != "80" {
		t.Errorf("did not properly ID http\n")
	}
}

func TestIdentifyServices2(t *testing.T) {
	nmap_output_2_results := [][]string{
		[]string{"21","open","ftp"},
		[]string{"22","open","ssh"},
		[]string{"23","open","telnet"},
		[]string{"25","open","smtp"},
		[]string{"53","open","domain"},
		[]string{"80","open","http"},
		[]string{"111","open","rpcbind"},
		[]string{"139","open","netbios-ssn"},
		[]string{"445","open","microsoft-ds"},
		[]string{"512","open","exec"},
		[]string{"513","open","login"},
		[]string{"514","open","shell"},
		[]string{"1099","open","rmiregistry"},
		[]string{"1524","open","ingreslock"},
		[]string{"2049","open","nfs"},
		[]string{"2121","open","ccproxy-ftp"},
		[]string{"3306","open","mysql"},
		[]string{"3389","closed","ms-wbt-server"},
		[]string{"5432","open","postgresql"},
		[]string{"5900","open","vnc"},
		[]string{"6000","open","X11"},
		[]string{"6667","open","irc"},
		[]string{"8009","open","ajp13"},
		[]string{"8180","open","unknown"},
	}
	identified := identifyServices(nmap_output_2)
	if len(identified) != len(nmap_output_2_results) {
		t.Errorf("didn't identify all running services\n")
	}
	for i := 0; i < len(nmap_output_2_results); i ++ {
		if identified[i].name != nmap_output_2_results[i][2] {
			t.Errorf("issues with service name parsing (%v:%v)", identified[i].name, nmap_output_2_results[i][2])
		}
	}
}








