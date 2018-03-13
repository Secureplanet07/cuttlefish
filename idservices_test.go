package main

import (
	"os"
	"fmt"
	"testing"
	"path/filepath"
)

var unicorn_output_1 = `
TCP open	             ftp[   21]		from 10.11.1.22  ttl 64 
TCP open	             ssh[   22]		from 10.11.1.22  ttl 64 
TCP open	          telnet[   23]		from 10.11.1.22  ttl 64 
TCP open	            smtp[   25]		from 10.11.1.22  ttl 64 
TCP open	            http[   80]		from 10.11.1.22  ttl 64 
TCP open	          sunrpc[  111]		from 10.11.1.22  ttl 64 
TCP open	     netbios-ssn[  139]		from 10.11.1.22  ttl 64 
TCP open	            smux[  199]		from 10.11.1.22  ttl 64 
TCP open	           https[  443]		from 10.11.1.22  ttl 64 
TCP open	           pop3s[  995]		from 10.11.1.22  ttl 64 
TCP closed	     filenet-tms[32768]		from 10.11.1.22  ttl 64 
`

var unicorn_service_1 = "TCP open ftp[ 21]from 10.11.1.22 ttl 64 "
var unicorn_service_2 = "TCP open ssh[ 22]from 10.11.1.22 ttl 64 "
var unicorn_service_3 = "TCP open filenet-tms[32768]from 10.11.1.22 ttl 64"

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

func TestIdentifyUnicornServices1(t *testing.T) {
	/**/
	identified := identifyServices("unicorn", unicorn_output_1, "127.0.0.1")
	
	if len(identified) != 11 {
		error_string := fmt.Sprintf("did not properly ID services (%v/11)", len(identified))
		t.Errorf(error_string)
	} //*/
}

func TestGetUnicornServiceName(t *testing.T) {
	name1 := getUnicornServiceName(unicorn_service_1)
	name2 := getUnicornServiceName(unicorn_service_2)
	name3 := getUnicornServiceName(unicorn_service_3)
	if name1 != "ftp" {
		error_string := fmt.Sprintf("expected (ftp), got (%v)", name1)
		t.Errorf(error_string)
	}
	if name2 != "ssh" {
		error_string := fmt.Sprintf("expected (ssh), got (%v)", name1)
		t.Errorf(error_string)
	}
	if name3 != "filenet-tms" {
		error_string := fmt.Sprintf("expected (filenet-tms), got (%v)", name1)
		t.Errorf(error_string)
	}
}

func TestGetUnicornServicePort(t *testing.T) {
	port1 := getUnicornServicePort(unicorn_service_1)
	port2 := getUnicornServicePort(unicorn_service_2)
	port3 := getUnicornServicePort(unicorn_service_3)
	if port1 != "21" {
		error_string := fmt.Sprintf("expected (21), got (%v)", port1)
		t.Errorf(error_string)
	}
	if port2 != "22" {
		error_string := fmt.Sprintf("expected (22), got (%v)", port2)
		t.Errorf(error_string)
	}
	if port3 != "32768" {
		error_string := fmt.Sprintf("expected (32768), got (%v)", port3)
		t.Errorf(error_string)
	}
}

func TestGetUnicornServiceStatus(t *testing.T) {
	status1 := getUnicornServiceStatus(unicorn_service_1)
	status2 := getUnicornServiceStatus(unicorn_service_2)
	status3 := getUnicornServiceStatus(unicorn_service_3)
	if status1 != "open" {
		error_string := fmt.Sprintf("expected (open), got (%v)", status1)
		t.Errorf(error_string)
	}
	if status2 != "open" {
		error_string := fmt.Sprintf("expected (open), got (%v)", status2)
		t.Errorf(error_string)
	}
	if status3 != "open" {
		error_string := fmt.Sprintf("expected (open), got (%v)", status3)
		t.Errorf(error_string)
	}
}

func TestCondenseSpacesToSingle(t *testing.T) {
	test_string_1 := "                   "
	test_string_2 := "this   is       a test"
	condensed_string_1 := condenseSpacesToSingle(test_string_1)
	condensed_string_2 := condenseSpacesToSingle(test_string_2)
	if len(condensed_string_1) > 1 {
		error_string := fmt.Sprintf("expected (%v), got (%v)", " ", condensed_string_1)
		t.Errorf(error_string)
	}
	if len(condensed_string_2) > 14 {
		error_string := fmt.Sprintf("expected (%v), got (%v)", "this is a test", condensed_string_2)
		t.Errorf(error_string)
	}
}

func TestIdentifyServices1(t *testing.T) {
	identified := identifyServices("nmap",nmap_output_1, "127.0.0.1")
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
	identified := identifyServices("nmap",nmap_output_2, "127.0.0.1")
	if len(identified) != len(nmap_output_2_results) {
		t.Errorf("didn't identify all running services\n")
	}
	for i := 0; i < len(nmap_output_2_results); i ++ {
		if identified[i].name != nmap_output_2_results[i][2] {
			t.Errorf("issues with service name parsing (%v:%v)", identified[i].name, nmap_output_2_results[i][2])
		}
	}
}

/*
func TestMakeServiceScanList(t *testing.T) {
	identified := identifyServices(nmap_output_2)
	service_scan_list := makeServiceScanList("t3st1ng", identified)
	if len(service_scan_list) != 7 {
		t.Errorf("expected 7 services \n(\n\tssh,\n\tsmtp,\n\tsnmp,\n\tdomain,\n\tftp,\n\tmicrosoft-ds,\n\tms-sql\n)\n...identified %v", len(service_scan_list))
	}
} //*/


func TestRemoveDuplicateServices(t *testing.T) {
	service_list_1 := []service {
		service{"ssh", "127.0.0.1", "22", "initialized"},
		service{"http", "127.0.0.1", "80", "initialized"},
		service{"ssh", "127.0.0.1", "31337", "initialized"},
	}
	service_list_2 := []service {
		service{"ssh", "127.0.0.1", "22", "initialized"},
	}

	dups_1 := removeDuplicateServices(service_list_1)
	if len(dups_1) < 3 {
		t.Errorf("expected 3 services, got %v", len(dups_1))
	}
	dups_2 := removeDuplicateServices(service_list_2)
	if len(dups_2) != 1 {
		t.Errorf("expected 1 service, got %v", len(dups_2))
	}
	dups_3 := append(dups_1, dups_2...)
	dups_3 = removeDuplicateServices(dups_3)
	if len(dups_3) != 3 {
		t.Errorf("expected 3 services, got %v", len(dups_3))
	}
}

/*
func addIdentScansToList(service_scan_list []scan, current_service *service) []scan {
	service_ports := getServicePortsFromScanList(service_scan_list)
	ident_scan_args := []string{
		current_service.target
	}
	// add all identified services ports to the scan args
	// to make 
	ident_scan_args = append(ident_scan_args, service_ports...)
	
}
*/

func TestAddIdentScansToList(t *testing.T) {
	service_list := []service {
		service{"ssh", "127.0.0.1", "22", "initialized"},
		service{"http", "127.0.0.1", "80", "initialized"},
		service{"ssh", "127.0.0.1", "31337", "initialized"},
	}
	service_ports := getServicePortsFromServiceList(service_list)
	if len(service_ports) != len(service_list) {
		t.Errorf("expected 3 service ports, got %v", len(service_ports))
	}
	service_scan_list := []scan{}
	current_service := service{"ident", "127.0.0.1", "113", "initialized"}
	ident_scan := addIdentScansToList(service_scan_list, service_list, &current_service)
	// +2 because the args have the target IP and service port in addition to other identified services
	if len(ident_scan[0].args) != len(service_list) + 2 {
		t.Errorf("expected %v service ports in ident scan, got %v", len(service_list) + 2, len(ident_scan[0].args))
	}
}

func TestPerformSecondaryScansFromPreviousRun(t *testing.T) {
	target := "127.0.0.1"
	current_dir, _ := os.Getwd()
	target_file_path := filepath.Join(current_dir, "test/test_recon.cuttlelog")
	identified_services := identifyServicesFromNmapOututFile(target_file_path, target)
	fmt.Printf("%v", identified_services)
	if len(identified_services) != 4 {
		t.Errorf("expected 4 services, got %v", len(identified_services))
	}
}






