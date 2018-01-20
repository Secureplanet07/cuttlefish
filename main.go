package main

import (
	"os"
	"fmt"
	//"net"
	"flag"
	"sync"
	"time"
	"regexp"
	"strings"
	"syscall"
	"os/exec"
	"os/signal"
	"io/ioutil"
	"encoding/json"
	"path/filepath"
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
// output log file
var logging = false
var logfile_path string

// track number of prints to properly format 'flush' printing
var number_of_prints = 0

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
	args []string
	results string
	status string
	elapsed float64
}

// struct to hold information about an id'd service
type service struct {
	name string
	port string
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
	regularPrint("[*] loading aws credentials from ./creds.json", logging, true)
	var aws_creds creds
	rawjson, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		print_string := fmt.Sprintf("\t[-] %v", err.Error())
		regularPrint(print_string, logging, true)
		os.Exit(1)
	}
	err = json.Unmarshal(rawjson, &aws_creds)
	if err != nil {
		print_string := fmt.Sprintf("\t[-] %v", err.Error())
		regularPrint(print_string, logging, true)
		os.Exit(1)
	}
	if len(aws_creds.AccessKey) == 0 || len(aws_creds.SecretKey) == 0 {
		regularPrint("\t[-] keys not loaded successfully", logging, true)
		os.Exit(1)
	}
	regularPrint("\t[+] creds loaded from file successfully", logging, true)
	return aws_creds
}

// returns an authenticated AWS API session object to use
// for spinning up EC2 instances
func initializeAWSSession() *session.Session{
	// load the creds
	aws_creds := getCreds()
	
	regularPrint("[*] grabbing AWS session", logging, true)

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
		regularPrint(print_string, logging, true)
		os.Exit(0)
	}
	regularPrint("\t[+] successfully authenticated AWS session", logging, true)
	return sess
}

// performs a scan for a passed command
// command is an array of strings
func performScan(target string, scan_to_perform *scan) {
	scan_to_perform.mutex.RLock()
	scan_to_perform.status = "running"
	scan_to_perform.mutex.RUnlock()
	out, err := exec.Command(scan_to_perform.command, scan_to_perform.args...).Output()
	if err != nil {
		error_string := fmt.Sprintf("[!] error running (%v)\n\t%v", 
			scan_to_perform.command, err)
		colorPrint(error_string, string_format.red, logging, true)
		os.Exit(1)
	}
	scan_to_perform.mutex.RLock()
	scan_to_perform.results = string(out)
	scan_to_perform.status = "complete"
	scan_to_perform.mutex.RUnlock()
}

func scanProgress(scans []scan, target string, scan_channel chan bool) {
	start_time := time.Now()
	finished := 0
	// log the starts
	for i := 0; i < len(scans); i++ {
		to_write := fmt.Sprintf("\t[*] scan: %v (%v) [time elapsed: %.2fs]", scans[i].name, scans[i].status, scans[i].elapsed)
		if logging {
			log(to_write)
		}
	}
	
	for 1 > finished {
		var completion_statuses []int
		for i := 0; i < len(scans); i++ {
			scans[i].mutex.RLock()
			current_time := time.Now()
			time_elapsed := current_time.Sub(start_time).Seconds()
			scans[i].elapsed = time_elapsed
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
	// log the finishes
	for i := 0; i < len(scans); i++ {
		to_write := fmt.Sprintf("\t[*] scan: %v (%v) [time elapsed: %.2fs]", scans[i].name, scans[i].status, scans[i].elapsed)
		if logging {
			log(to_write)
		}
	}
	// update tracked prints for number of scans
	number_of_prints += len(scans)
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

func log(message string) {
	var f *os.File
	var err error
	// path to logfile doesn't exist, create the file
	if _, err := os.Stat(logfile_path); os.IsNotExist(err) {
		f, err = os.Create(logfile_path)
		f.Close()
	}
	defer f.Close()
	if err != nil {
		error_mes := fmt.Sprintf("[-] cannot create log file\n\t%v\n", err)
		colorPrint(error_mes, string_format.red, false, true)
		os.Exit(1)
	}
	f, err = os.OpenFile(logfile_path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		error_mes := fmt.Sprintf("[-] cannot open log file\n\t%v\n", err)
		colorPrint(error_mes, string_format.red, false, true)
		os.Exit(1)
	}
	to_write := fmt.Sprintf("%v\n", message)
	num, err := f.WriteString(to_write)
	if err != nil && num > 0 {
		error_mes := fmt.Sprintf("[-] cannot write to log file\n\t%v\n", err)
		colorPrint(error_mes, string_format.red, false, true)
		os.Exit(1)
	}
}

func regularPrint(print_string string, logging bool, tracking bool) {
	if logging {
		log(print_string)
	}
	if tracking {
		number_of_prints += 1
	}
	fmt.Printf("%v\n", print_string)
}

func colorPrint(print_string string, color string, logging bool, tracking bool) {
	if logging {
		log(print_string)
	}
	if tracking {
		number_of_prints += 1
	}
	fmt.Printf("%v%v%v\n", color, print_string, string_format.end)
}

func cleanup() {
	colorPrint("\n[!] caught Ctl-C ... cleaning up", string_format.yellow, logging, true)
	os.Exit(1)
}

func outputProgress(scans []scan) {
	x, _ := terminal.Width()
	//y, _ := terminal.Height()

	// this will buffer our output updating the scan results
	// without overwriting previous command line output
	output_height := (number_of_prints + 1) //% int(y)
	fmt.Printf("\033[%v;0H", output_height)
	// overwrite with blank lines 
	for i := 0; i < len(scans); i++ {
		blank_line := strings.Repeat(" ", int(x))
		fmt.Println(blank_line)
	}
	fmt.Printf("\033[%v;0H", output_height)
	// overwrite with updated scan results
	for i := 0; i < len(scans); i++ {
		to_write := fmt.Sprintf("\t[*] scan: %v (%v) [time elapsed: %.2fs]", scans[i].name, scans[i].status, scans[i].elapsed)
		scans[i].mutex.RLock()
		if scans[i].status == "complete" {
			colorPrint(to_write, string_format.green, false, false)
		} else if scans[i].status == "running" {
			colorPrint(to_write, string_format.yellow, false, false)
		} else if scans[i].status == "error" {
			colorPrint(to_write, string_format.red, false, false)
		} else {
			colorPrint(to_write, string_format.blue, false, false)
		}
		scans[i].mutex.RUnlock()
	}
}

func identifyServices(nmap_output string) []service {
	// grab '22/tcp' from the beginning of the line
	var validService = regexp.MustCompile(`^\d+/[a-z]+`)
	// grab '  ssh  ' from the validated line
	var serviceType = regexp.MustCompile(`  \w+  `)
	var identified_services []service
	all_lines := strings.Split(nmap_output, "\n")
	for i := 0; i < len(all_lines); i++  {
		service_string := validService.FindString(all_lines[i])
		if len(service_string) > 0 {
			service_port := strings.Split(service_string, "/")[0]
			service_name := serviceType.FindString(all_lines[i])
			service_name = strings.Replace(service_name, "  ", "", 2)
			new_service := service{service_name, service_port}
			identified_services = append(identified_services, new_service)
		}
	}
	return identified_services
}

// TODO: transforms a list of services into a list of scans
// converts services identified by nmap output into `scan` structs for
// downstream processing.
func makeServiceScanList([]service) []scan {
	return []scan{}
}

func main() {
	// sig-term handler
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		os.Exit(1)
	}()

	// parse out the flags passed
	target		:= flag.String("target", "d34db33f", "IP address of target machine")
	tentacles 	:= flag.Int("tentacles", 0, "number of AWS 'tentacles' (default=0)")
	output_path	:= flag.String("logfile", "~/Desktop", "location of output log file")
	flag.Parse()

	// set up the log file path
	logfile_name := fmt.Sprintf("%v-%v-.cuttlelog", *target, time.Now())
	logfile_path = filepath.Join(*output_path, logfile_name)

	// clear the terminal
	print("\033[H\033[2J")
	// make sure we're running as root
	regularPrint("[~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~]", logging, true)
	regularPrint("[~~~~~~~~~~~~\twelcome to cuttlefish\t~~~~~~~~~~~]", logging, true)
	regularPrint("[~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~]", logging, true)
	// var aws_session *session.Session
	if *target == "d34db33f" {
		regularPrint("[!] specify a target with '-target=TARGET_IP'", logging, true)
		os.Exit(0)
	}
	if *tentacles > 0 {
		// aws_session := initializeAWSSession()
		initializeAWSSession()	
	}
	// runmode summary
	opt_1 := fmt.Sprintf("[~~~~~~~~~~~~~~~~~   run options   ~~~~~~~~~~~~~~~~]")
	logfile_path_string := fmt.Sprintf("[*] logging to %v", logfile_path)
	opt_2 := fmt.Sprintf("[*] target 				%v", *target)
	opt_3 := fmt.Sprintf("[*] aws tentacles 				%v", *tentacles)
	opt_4 := fmt.Sprintf("[*] enum modes: nmap")
	regularPrint(opt_1, logging, true)
	regularPrint(logfile_path_string, logging, true)
	regularPrint(opt_2, logging, true)
	regularPrint(opt_3, logging, true)
	regularPrint(opt_4, logging, true)
	
	// initialized the scans
	var scans []scan
	// nmap -vv -Pn -A -sC -sS -T 4 -p- TARGET
	nmap_scan := scan{&sync.RWMutex{}, "initial nmap recon", "nmap", []string{}, "", "initialized", 0}
	if os.Getuid() == 0 {
		getuid_string := fmt.Sprintf("[+] root privs enabled (GUID: %v), script scanning with nmap", os.Getuid())
		colorPrint(getuid_string, string_format.green, logging, true)
		nmap_scan.args = []string{"-vv", "-Pn", "-A", "-sC", "-sS", "-T4", "-p-", *target}
	} else {
		getuid_string := fmt.Sprintf("[!] not executed as root (GUID: %v), script scanning not performed", os.Getuid())
		colorPrint(getuid_string, string_format.yellow, logging, true)
		// "-vv", "-Pn", "-A", "-sS", "-T4", "-p-", 
		//nmap_scan.args = []string{"-vv", "-Pn", "-A", "-T4", "-p-", *target}
		nmap_scan.args = []string{*target}
	}
	scans = append(scans, nmap_scan)

	// setup the scan channel
	recon_scan_channel := make(chan bool)
	
	// pass by reference so we update the shared struct value
	go performScan(*target, &scans[0])
	go scanProgress(scans, *target, recon_scan_channel)
	// block on recon scan channel 
	<-recon_scan_channel
	log(scans[0].results)
	
	// now let's find services from the recon scan results
	identified_services := identifyServices(scans[0].results)
	if len(identified_services) == 0 {
		colorPrint("[-] no services identified", string_format.red, logging, true)
		colorPrint("\t[!] try different scan options", string_format.yellow, logging, true)
		os.Exit(0)
	}
	colorPrint("[+] identified running services", string_format.green, logging, true)
	for i := 0; i < len(identified_services); i++ {
		service_string := fmt.Sprintf("\t[+] %v (%v)", 
			identified_services[i].name,
			identified_services[i].port)
		colorPrint(service_string, string_format.green, logging, true)
	}

	/* start new scans based on the service info
	scans = makeServiceScanList(identified_services)
	service_scan_channel := make(chan bool)
	trackedPrint("[*] performing service scans")
	for i := 0; i < len(scans); i++ {
		go performScan(*target, &scans[i])
	} //*/

	complete_string := fmt.Sprintf("[+] cuttlefish scan of %v complete!\n", *target)
	regularPrint(complete_string, logging, true)
}





