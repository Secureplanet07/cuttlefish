package main

import (
	"os"
	"fmt"
	//"net"
	"flag"
	"sync"
	"strings"
	"os/exec"
	"io/ioutil"
	"encoding/json"
	terminal "github.com/wayneashleyberry/terminal-dimensions"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
	//"github.com/aws/aws-sdk-go/service/ec2"
)

/*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
~~~~~~~ global structs and vars ~~~~~~
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
// track number of prints to properly format 'flush' printing
var number_of_prints int

// struct to hold string value of AWS credentials
type creds struct {
	AccessKey string
	SecretKey string
}

// struct to hold information about a scan
type scan struct {
	mutex *sync.RWMutex
	name string
	command string
	results string
	status string
}

// color escape characters for terminal printing
var string_format = struct {
	header string
	blue string
	green string
	yellow string
	red string
	end string
	bold string
	underl string
}{
	header: "\033[95m",
	blue: 	"\033[94m",
	green: 	"\033[92m",
	yellow: "\033[93m",
	red: 	"\033[91m",
	end: 	"\033[0m",
	bold: 	"\033[1m",
	underl: "\033[4m",
}

// getCreds()
//	pull aws creds from creds.json
func getCreds() creds {
	trackedPrint("[*] loading aws credentials from ./creds.json")
	var aws_creds creds
	rawjson, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		print_string := fmt.Sprintf("\t[-] %v", err.Error())
		trackedPrint(print_string)
		os.Exit(1)
	}
	err = json.Unmarshal(rawjson, &aws_creds)
	if err != nil {
		print_string := fmt.Sprintf("\t[-] %v", err.Error())
		trackedPrint(print_string)
		os.Exit(1)
	}
	if len(aws_creds.AccessKey) == 0 || len(aws_creds.SecretKey) == 0 {
		trackedPrint("\t[-] keys not loaded successfully")
		os.Exit(1)
	}
	trackedPrint("\t[+] creds loaded from file successfully")
	return aws_creds
}

// returns an authenticated AWS API session object to use
// for spinning up EC2 instances
func initializeAWSSession() *session.Session{
	// load the creds
	aws_creds := getCreds()
	
	trackedPrint("[*] grabbing AWS session")

	// set environmental variables
	akid_arg := []string{"AWS_ACCESS_KEY_ID", aws_creds.AccessKey}
	secret_arg := []string{"AWS_SECRET_ACCESS_KEY", aws_creds.SecretKey}
	env_sets := [][]string{akid_arg, secret_arg}
	
	for i := 0; i < len(env_sets); i++ {
		os.Setenv(env_sets[i][0], env_sets[i][1])
	}
	// get a new aws session
	creds := credentials.NewEnvCredentials()
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: creds,
	})
	// make sure we got an authenticated session
	_, crederr := sess.Config.Credentials.Get()
	if crederr != nil {
		print_string := fmt.Sprintf("\t[-] invalid credentials %v", err.Error())
		trackedPrint(print_string)
		os.Exit(0)
	}
	trackedPrint("\t[+] successfully authenticated AWS session")
	return sess
}

// performs an initial nmap scan on the target
func nmapScan(target string, nmap_scan *scan) {
    nmap_scan.mutex.RLock()
	nmap_scan.status = "running"
	nmap_scan.mutex.RUnlock()
	command_string := fmt.Sprintf("nmap %v", target)
	out, err := exec.Command("nmap", target).Output()
	if err != nil {
		error_string := fmt.Sprintf("[!] error running (%v)\n%v\n", 
			command_string, err)
		trackedPrint(error_string)
		os.Exit(1)
	}
	nmap_scan.mutex.RLock()
	nmap_scan.results = string(out)
	nmap_scan.status = "complete"
	nmap_scan.mutex.RUnlock()
}

// a test scan 
func echoScan(target string, echo_scan *scan) {
	result_string := fmt.Sprintf("echo returning for %v", target)
	echo_scan.mutex.RLock()
	echo_scan.status = "running"
	echo_scan.results = result_string
	echo_scan.status = "complete"
	echo_scan.mutex.RUnlock()
}

func scanProgress(scans []scan, target string, scan_channel chan bool) {
	finished := 0
	for 1 > finished {
		var completion_statuses []int
		for i := 0; i < len(scans); i++ {
			scans[i].mutex.RLock()
			if scans[i].status == "complete" {
				completion_statuses = append(completion_statuses, 1)
			} else {
				completion_statuses = append(completion_statuses, 0)
			}
			scans[i].mutex.RUnlock()
		}
		if allSame(completion_statuses) && completion_statuses[0] == 1 {
			finished = 1
		} else {
			outputProgress(scans)
		}
	}
	scan_channel <- true
}

func allSame(ints []int) bool {
	for i := 0; i < len(ints); i++ {
		if ints[i] != ints[0] {
            return false
        }
	}
	return true
}

func trackedPrint(print_string string) {
	fmt.Printf("%v\n", print_string)
	number_of_prints += 1
}

func trackedColorPrint(print_string string, color string) {
	fmt.Printf("%v%v%v\n", color, print_string, string_format.end)
	number_of_prints += 1
}

func colorPrint(print_string string, color string) {
	fmt.Printf("%v%v%v\n", color, print_string, string_format.end)
}

func outputProgress(scans []scan) {
	x, _ := terminal.Width()
    //y, _ := terminal.Height()

    // this will buffer our output updating the scan results
    // without overwriting previous command line output
    output_height := number_of_prints + 1
	fmt.Printf("\033[%v;0H", output_height)
	// overwrite with blank lines 
	for i := 0; i < len(scans); i++ {
		blank_line := strings.Repeat(" ", int(x))
		fmt.Println(blank_line)
	}
	fmt.Printf("\033[%v;0H", output_height)
	// overwrite with updated scan results
	for i := 0; i < len(scans); i++ {
		to_write := fmt.Sprintf("\t[*] scan: %v (%v)", scans[i].name, scans[i].status)
		scans[i].mutex.RLock()
		if scans[i].status == "complete" {
			colorPrint(to_write, string_format.green)
		} else if scans[i].status == "running" {
			colorPrint(to_write, string_format.yellow)
		} else if scans[i].status == "error" {
			colorPrint(to_write, string_format.red)
		} else {
			colorPrint(to_write, string_format.blue)
		}
		scans[i].mutex.RUnlock()
	}
}

func main() {
	// set globals 
	number_of_prints = 0
	// parse out the flags passed
	target		:= flag.String("target", "d34db33f", "IP address of target machine")
	tentacles 	:= flag.Int("tentacles", 0, "number of AWS 'tentacles' (default=0)")
	flag.Parse()

	// clear the terminal
	print("\033[H\033[2J")
	trackedPrint("[~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~]")
	trackedPrint("[~~~~~~~~~~~~\twelcome to cuttlefish\t~~~~~~~~~~~]")
	trackedPrint("[~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~]")
	// var aws_session *session.Session
	if *target == "d34db33f" {
		trackedPrint("[!] specify a target with '-target=TARGET_IP'")
		os.Exit(0)
	}
	if *tentacles > 0 {
		// aws_session := initializeAWSSession()
		initializeAWSSession()	
	}
	// runmode summary
	opt_1 := fmt.Sprintf("[~~~~~~~~~~~~~~~~~   run options   ~~~~~~~~~~~~~~~~]")
	opt_2 := fmt.Sprintf("[*] target 				%v ]", *target)
	opt_3 := fmt.Sprintf("[*] aws tentacles 				%v ]", *tentacles)
	opt_4 := fmt.Sprintf("[*] enum modes: nmap")
	trackedPrint(opt_1)
	trackedPrint(opt_2)
	trackedPrint(opt_3)
	trackedPrint(opt_4)
	
	// initialized the scans
	var scans []scan
	nmap_scan := scan{&sync.RWMutex{}, "nmap", "nmap", "", "initialized"}
	echo_scan := scan{&sync.RWMutex{}, "echo", "echo", "", "initialized"}
	scans = append(scans, nmap_scan)
	scans = append(scans, echo_scan)

	// setup the scan channel
	scan_channel := make(chan bool)
	
	// pass by reference so we update the shared struct value
	go nmapScan(*target, &scans[0])
	go echoScan(*target, &scans[1])
	go scanProgress(scans, *target, scan_channel)
	<-scan_channel
	complete_string := fmt.Sprintf("[+] scan of %v complete!\n", *target)
	trackedPrint(complete_string)
}





