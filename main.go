package main

import (
	"os"
	"fmt"
	"flag"
	"math"
	"sync"
	"time"
	"bytes"
	"regexp"
	"strings"
	"syscall"
	"os/exec"
	"os/user"
	"os/signal"
	"path/filepath"
	terminal "github.com/wayneashleyberry/terminal-dimensions"
)

/*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
~~~~~~~ global structs and vars ~~~~~~
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

// debug?
var debug = false

// start time (for log files)
var scan_start = time.Now()
var term_width, _ = terminal.Width()
var term_height, _ = terminal.Height()

var iteration = 0
var status_spin = []string{"\\","|","/","-"}

// output log file
var logging = true
var logfile_root_path string
var logfile_path string

// location of enum scripts
var working_dir,_ = os.Getwd()
var script_dir = filepath.Join(working_dir, "scripts")

// arguments to scans
//
var hydra_default_user_wordlist = 	"/root/Documents/tools/SecLists/Usernames/top_shortlist.txt"
var hydra_default_user_passlist = 	"/root/Documents/tools/SecLists/Passwords/best1050.txt"
var gobuster_default_dirlist = 		"/root/Documents/tools/SecLists/Discovery/Web_Content/raft-medium-directories.txt"
var gobuster_default_filelist = 	"/root/Documents/tools/SecLists/Discovery/Web_Content/raft-medium-files.txt"
var gobuster_default_cgilist = 		"/root/Documents/tools/SecLists/Discovery/Web_Content/cgis.txt"
var smtp_default_namelist = 		"/root/Documents/tools/SecLists/Usernames/top_shortlist.txt"
/*
var hydra_default_user_wordlist = 	"/Users/coastal//Documents/tools/SecLists/Usernames/top_shortlist.txt"
var hydra_default_user_passlist = 	"/Users/coastal/Documents/tools/SecLists/Passwords/best1050.txt"
var gobuster_default_dirlist = 		"/Users/coastal/Documents/tools/SecLists/Discovery/Web_Content/raft-medium-directories.txt"
var gobuster_default_filelist = 	"/Users/coastal/Documents/tools/SecLists/Discovery/Web_Content/raft-medium-files.txt"
var gobuster_default_cgilist =		"/Users/coastal/Documents/tools/SecLists/Discovery/Web_Content/cgis.txt"
var smtp_default_namelist = 		"/Users/coastal/Documents/tools/SecLists/Usernames/top_shortlist.txt"
//*/

// stuff to keep track of the prints so we can update the terminal ouput
// properly when we print past the end of the terminal
var previous_prints = []previous_print{}
type previous_print struct {
	print_color string // "regular" or the color
	print_string string
}

// struct to hold string value of AWS credentials
type creds struct {
	AccessKey string
	SecretKey string
}

// struct to hold information about a scan
type scan struct {
	mutex *sync.RWMutex
	scan_type string
	name string 		// also logfile name
	command string
	args []string
	results string
	status string
	elapsed float64
	logged bool
	error_message string
	scan_service *service
	start_time time.Time
}

// struct to hold information about an id'd service
type service struct {
	name string
	target string
	port string
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

func cleanup(scans []scan) {
	if !allScansComplete(scans) {
		for i := 0; i < len(scans); i++ {
			current_scan := scans[i]
			// if any of the scans were still running, this means
			// that the scan run was not complete and therefore
			// would not be logged in the main log file

			// the completed scans would have individual log files
			// the running scans would have neither
			
			if current_scan.status == "running" {
				scan_logfile_path := formatScanLogfile(current_scan)
				log(scan_logfile_path, "[*] caught Ctl-C ... exiting")
				log(scan_logfile_path, current_scan.results)
			}
			scan_formatted := formatScan(&current_scan)
			log(logfile_path, scan_formatted)
		}
	}
	ctl_c_string := fmt.Sprintf("\n[!] caught Ctl-C ... cleaning up%v", string_format.end)
	colorPrint(ctl_c_string, string_format.yellow, logging, true)
	os.Exit(0)
}

func allSame(ints []int) bool {
	for i := 0; i < len(ints); i++ {
		if ints[i] != ints[0] {
			return false
		}
	}
	return true
}

func allScansComplete(scans []scan) bool {
	var completion_statuses []int
	for i := 0; i < len(scans); i++ {
		current_scan := scans[i]
		current_scan.mutex.RLock()
		if current_scan.status == "complete" || current_scan.status == "error" {
			completion_statuses = append(completion_statuses, 1)
		} else {
			completion_statuses = append(completion_statuses, 0)
		}
		current_scan.mutex.RUnlock()
	}
	all_same_bool := allSame(completion_statuses) && completion_statuses[0] == 1
	return all_same_bool
}

func log(log_filepath string, message string) {
	if logging {
		var f *os.File
		var err error
		// path to logfile doesn't exist, create the file
		if _, err := os.Stat(log_filepath); os.IsNotExist(err) {
			f, err = os.Create(log_filepath)
			f.Close()
		}
		if err != nil {
			error_mes := fmt.Sprintf("[-] cannot create log file\n\t%v\n", err)
			colorPrint(error_mes, string_format.red, false, true)
			f.Close()
			os.Exit(1)
		}
		defer f.Close()
		f, err = os.OpenFile(log_filepath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			error_mes := fmt.Sprintf("[-] cannot open log file\n\t%v\n", err)
			colorPrint(error_mes, string_format.red, false, true)
			f.Close()
			os.Exit(1)
		}
		to_write := fmt.Sprintf("%v\n", message)
		num, err := f.WriteString(to_write)
		if err != nil && num > 0 {
			error_mes := fmt.Sprintf("[-] cannot write to log file\n\t%v\n", err)
			colorPrint(error_mes, string_format.red, false, true)
			f.Close()
			os.Exit(1)
		}
		f.Close()
	}
}

func addToPreviousPrints(print_color string, print_string string) {
	print_instance := previous_print{print_color, print_string}
	previous_prints = append(previous_prints, print_instance)
}

func regularPrint(print_string string, logging bool, tracking bool) {
	if logging {
		log(logfile_path, print_string)
	}
	if tracking {
		addToPreviousPrints("regular", print_string)
	}
	fmt.Printf("%v\n", print_string)
}

func colorPrint(print_string string, color string, logging bool, tracking bool) {
	if logging {
		log(logfile_path, print_string)
	}
	if tracking {
		addToPreviousPrints(color, print_string)
	}
	fmt.Printf("%v%v%v\n", color, print_string, string_format.end)
}

func scanPrint(scan_to_print *scan, logging bool, tracking bool) {
	scan_formatted := formatScan(scan_to_print)
	scan_color := ""
	if scan_to_print.status == "complete" {
		scan_color = string_format.green
	} else if scan_to_print.status == "error" {
		scan_color = string_format.red
	} else if scan_to_print.status == "initialized" {
		scan_color = string_format.blue
	} else {
		scan_color = string_format.yellow
	}
	scan_color_formatted := fmt.Sprintf("%v%v%v\n", 
		scan_color, 
		scan_formatted, 
		string_format.end,
	)
	if tracking {
		if logging {
			log(logfile_path, scan_formatted)
		}
		addToPreviousPrints(scan_color, scan_formatted)
	}
	fmt.Printf(scan_color_formatted)
}

func previousPrint(previous_print_instance previous_print) {
	if previous_print_instance.print_color == "regular" {
		regularPrint(previous_print_instance.print_string, false, false)
	} else {
		colorPrint(
			previous_print_instance.print_string, 
			previous_print_instance.print_color, 
			false, 
			false,
		)
	}
}

func tabsFromNameLength(name string) int {
	max_len := 17
	diff := math.Abs(float64(max_len) - float64(len(name)))
	tabs := 3 - int(math.Floor(7 / float64(diff)))
	if tabs <= 0 {
		return 1
	}
	return tabs
}

// produces string of command + args that was passed to the 
// command line from a scan struct
func scanAsCommandLine(current_scan *scan) string {
	command_string := bytes.Buffer{}
	command_string.WriteString(current_scan.command)
	command_string.WriteString(" ")
	for i := 0; i < len(current_scan.args); i++ {
		to_write := fmt.Sprintf("%v ", current_scan.args[i])
		command_string.WriteString(to_write)
	}
	return command_string.String()
}

// format scan for output
func formatScan(current_scan *scan) string {
	status_character_idx := int(math.Floor(float64(iteration)/1)) % len(status_spin)
	status_character := status_spin[status_character_idx]
	number_of_tabs := tabsFromNameLength(current_scan.name)
	port_padding := strings.Repeat("\t", number_of_tabs)
	status_padding := "\t"
	current_time := time.Now()

	if current_scan.status == "error" {
		status_padding = "\t\t"
		status_character = "!"
	} else if current_scan.status == "complete" {
		status_character = "+"
	} else {
		// update the elapsed time
		time_elapsed := current_time.Sub(current_scan.start_time).Seconds()
		current_scan.elapsed = time_elapsed
	}

	formatted_scan := fmt.Sprintf("\t[%v] scan: %v%v[port:%v]\t(%v)%v[time elapsed: %.2fs]", 
		status_character, 
		current_scan.name, 
		port_padding, 
		current_scan.scan_service.port, 
		current_scan.status, 
		status_padding, 
		current_scan.elapsed,
	)

	return formatted_scan
}

func formatScanLogfile(current_scan scan) string {
	scan_logfile_name := fmt.Sprintf("%v-port%v-%v.cuttlelog", 
		current_scan.scan_service.target,
		current_scan.scan_service.port,
		current_scan.name,
	)
	scan_logfile_path := filepath.Join(logfile_root_path, scan_logfile_name)
	return scan_logfile_path
}

func addScanToPreviousPrints(current_scan scan) {
	print_color := ""
	scan_formatted := formatScan(&current_scan)
	if current_scan.status == "complete" {
		print_color = string_format.green
	} else if current_scan.status == "running" {
		print_color = string_format.yellow
	} else if current_scan.status == "error" {
		print_color = string_format.red
	} else {
		print_color = string_format.blue
	}
	addToPreviousPrints(print_color, scan_formatted)
}

func addScansToPreviousPrints(scans []scan) {
	for i := 0; i < len(scans); i++ {
		addScanToPreviousPrints(scans[i])
	}
}

func updateScansAndReturnCompletionReport(scans []scan) []int {
	var completion_statuses []int
	for i := 0; i < len(scans); i++ {
		current_scan := &scans[i]
		current_scan.mutex.RLock()
		if current_scan.status == "complete" || current_scan.status == "error" {
			completion_statuses = append(completion_statuses, 1)
			// gross..but prevents a logging:false, logged=true loop write
			if logging && (current_scan.logged == false) {
				current_scan.logged = true
				// write our actual scan loot outputs to a log file
				scan_logfile_path := formatScanLogfile(*current_scan)
				// log the error message if we error out
				if current_scan.status == "error" {
					// TODO: why we get cryptic error file output
					command_string := scanAsCommandLine(current_scan)
					command_string = fmt.Sprintf("[*] running command: %v", command_string)
					log(scan_logfile_path, command_string)
					log(scan_logfile_path, current_scan.error_message)
				} else {
					command_string := scanAsCommandLine(current_scan)
					command_string = fmt.Sprintf("[*] running command: %v", command_string)
					log(scan_logfile_path, command_string)
					log(scan_logfile_path, current_scan.results)
				}
			}
		} else {
			completion_statuses = append(completion_statuses, 0)
		}
		current_scan.mutex.RUnlock()
	}
	return completion_statuses
}

func scanProgress(scans []scan, target string, scan_channel chan bool) {
	start_time := time.Now()
	// initialize all scans with start_time of now
	for i := 0; i < len(scans); i++ {
		current_scan := scans[i]
		current_scan.start_time = start_time
	}
	finished := 0
	for 1 > finished {
		iteration += 1
		completion_statuses := updateScansAndReturnCompletionReport(scans)
		if allSame(completion_statuses) && completion_statuses[0] == 1 {
			// print the final state TODO: print them here
			// add them to the previousPrints so that they will print after completion
			addScansToPreviousPrints(scans)
			// we pass an empty list of scans because all of the previous scans will
			// still be printed (since we added them to previous_prints), but
			// outputProgress prints all of the scans in the []scan it is passed
			// regardless of progress status.
			// this way, all of our completed scans will be printed as a part of
			// previous_prints, and not printed again because they are not
			// sent in the scan array
			outputProgress([]scan{})
			finished = 1

		} else {
			outputProgress(scans)
			// without the sleep output gets nuts
			time.Sleep(100000000)
		}
	}
	// update tracked prints for number of scans
	scan_channel <- true
}

// returns the terminal y-axis coordinates for formatting print locations
// 		given a list of scans and a list of previous prints
// output:
//		(int) index of first previous print (inside of previous prints array)
//		(int) number of previous prints to print
//		(int) terminal height of first printed scan
func getTermPrintOffsets(scans []scan, previous_prints_array []previous_print) (int, int, int) {
	// -1 because the active print line takes up one space (cursor)
	num_prev_prints := int(term_height) - len(scans) - 1
	// if we are truncating, truncate by another space to make room for cursor
	if len(previous_prints) > (int(term_height) - 1) {
		num_prev_prints = num_prev_prints - 1
	}
	last_index := len(previous_prints)
	start_index := last_index - num_prev_prints
	if start_index < 0 {
		start_index = 0
	}
	if num_prev_prints > len(previous_prints_array) {
		num_prev_prints = len(previous_prints_array)
	}

	// this will buffer our output updating the scan results
	// it first clears any previous content that was on those lines
	output_height := num_prev_prints + 1 // to avoid overwriting 
	return start_index, num_prev_prints, output_height
}

func outputProgress(scans []scan) {
	// set these every time so that we can resize
	term_width, _ = terminal.Width()
	term_height, _ = terminal.Height()

	// this needs to write in the previous content to the terminal to
	// take care of the case in which we want to write to a position that is
	// past the end of the terminal

	// first clear the entire terminal
	print("\033[H\033[2J")
	// now write in the previous lines
	// there are a few conditions
	//	1. we write the number of previous lines, from the last-written, that
	//		leaves enough room for the active scans
	//	2. if there are more lines than can fit, only take the bottom n lines
	//		where n = term_height - len(scans)
	first_print_index, num_prev_prints_to_print, first_scan_print_height := getTermPrintOffsets(scans, previous_prints)
	
	for i:= 0; i < num_prev_prints_to_print; i++ {
		if debug {
			reformatted_print := fmt.Sprintf("%v %v", i+first_print_index, previous_prints[i+first_print_index])
			reformatted_prev_print := previous_prints[i+first_print_index]
			reformatted_prev_print.print_string = reformatted_print
			previousPrint(reformatted_prev_print)
		} else {
			previousPrint(previous_prints[i+first_print_index])
		}
	}
	// write in all the active scans below the previous content
	// this skips our write start to the height of the number of scans we have
	fmt.Printf("\033[%v;0H", first_scan_print_height)

	// overwrite with updated scan results
	for i := 0; i < len(scans); i++ {
		current_scan := &scans[i]
		current_scan.mutex.RLock()
		scanPrint(current_scan, false, false)
		current_scan.mutex.RUnlock()
	}
}

// identifies both open and closed running services
func identifyServices(nmap_output string, target string) []service {
	// grab '22/tcp' from the beginning of the line
	var validService = regexp.MustCompile(`^(\d+/[a-z]+)\s+\w+\s+[A-z,a-z,0-9,-]+`)
	// grab '  ssh  ' from the validated line
	//var serviceType = regexp.MustCompile(`\s[A-z,a-z,0-9,-]+`)
	var identified_services []service
	all_lines := strings.Split(nmap_output, "\n")
	for i := 0; i < len(all_lines); i++  {
		service_string := validService.FindString(all_lines[i])
		if len(service_string) > 0 {
			service_port := strings.Split(service_string, "/")[0]

			// holy mother of hacks...not proud of this
			service_name := strings.Replace(service_string, "     ", " ", 100)
			service_name = strings.Replace(service_string, "\t", " ", 100)
			service_name = strings.Replace(service_string, "   ", " ", 100)
			service_name = strings.Replace(service_string, "  ", " ", 100)
			service_name_list := strings.Split(service_string, " ")
			// we iterate through and remove all the empty strings
			parsed_service_name_list := []string{}
			for j := 0; j < len(service_name_list); j++ {
				if len(service_name_list[j]) > 0 {
					parsed_service_name_list = append(parsed_service_name_list, service_name_list[j])
				}
			}
			service_name = parsed_service_name_list[2]
			service_status := parsed_service_name_list[1]
			new_service := service{service_name, target, service_port, service_status}

			identified_services = append(identified_services, new_service)
		}
	}
	return identified_services
}

func removeDuplicateServices(service_list []service) []service {
	unique_services := []service{}
	for i := 0; i < len(service_list); i++ {
		hits := 0
		for j := 0; j < len(unique_services); j++ {
			if unique_services[j].name == service_list[i].name && 
				unique_services[j].port == service_list[i].port {
					hits += 1
			}
		}
		if hits == 0 {
			unique_services = append(unique_services, service_list[i])
		}
	}
	return unique_services
}
// performs a scan for a passed command
// command is an array of strings
func performScan(target string, scan_to_perform *scan) {
	scan_to_perform.mutex.RLock()
	scan_to_perform.status = "running"
	scan_to_perform.mutex.RUnlock()
	// scope vars to be handled by both os and cuttlefish scans
	var out []byte
	var err error
	// if our scan is an external command (nmap, dirb, etc)
	if scan_to_perform.scan_type == "os" {
		out, err = exec.Command(scan_to_perform.command, scan_to_perform.args...).Output()
		
		if err != nil {
			error_string := fmt.Sprintf("%v:%v", 
			scan_to_perform.name, err)
			/*
			error_log_string := fmt.Sprintf("[!] error running (%v)\n\t%v", 
			scan_to_perform.name, err)
			if logging {
				log(logfile_path, error_log_string)
			}
			//*/
			scan_to_perform.status = "error"
			scan_to_perform.error_message = error_string
		}
	}
	
	scan_to_perform.mutex.RLock()
	scan_to_perform.results = string(out)
	if scan_to_perform.status != "error" {
		scan_to_perform.status = "complete"
	}
	scan_to_perform.mutex.RUnlock()
}

/*
SMTP example
success condition
######## Scan started at Tue Jan 23 00:08:42 2018 #########
192.168.56.3: root exists
192.168.56.3: mysql exists
192.168.56.3: user exists
192.168.56.3: ftp exists
######## Scan completed at Tue Jan 23 00:08:42 2018 #########
*/
func postScanProcessing(completed_scan scan) {
	if completed_scan.command == "smtp" {

	}
}

func createOSServiceScan(current_service *service, name string, command string, args []string) scan {
	new_scan := scan{
		&sync.RWMutex{},
		"os",				// scan type
		name,
		command,
		args,
		"",					// results
		"initialized",		// status
		0,					// elapsed
		false,				// logged
		"",					// error message
		current_service,	// service
		scan_start,			// start_time
	}
	return new_scan
}

func addFTPScansToList(service_scan_list []scan, current_service *service) []scan {
	ftp_nmap_scan_args := []string{
		"-sV", 
		"-Pn", 
		"-vv", 
		"-p", 
		current_service.port, 
		"--script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,f" +
		"tp-vsftpd-backdoor,ftp-vuln-cve2010-4221", 
		current_service.target,
	}
	hydra_ftp_args := []string{
		"-L", 
		hydra_default_user_wordlist, 
		"-P", 
		hydra_default_user_passlist, 
		"-f", 
		"-u", 
		current_service.target, 
		"-s",
		 current_service.port, 
		 "ftp",
	}
	ftp_nmap_scan := createOSServiceScan(
		current_service, 
		"ftp-nmap-scan", 
		"nmap", 
		ftp_nmap_scan_args,
	)
	hydra_ftp_scan := createOSServiceScan(
		current_service, 
		"hydra-ftp-brute", 
		"hydra", 
		hydra_ftp_args,
	)
	service_scan_list = append(service_scan_list, ftp_nmap_scan)
	service_scan_list = append(service_scan_list, hydra_ftp_scan)
	return service_scan_list
}

func addSSHScansToList(service_scan_list []scan, current_service *service) []scan {
	hydra_args := []string{
		"-L", 
		hydra_default_user_wordlist, 
		"-P", 
		hydra_default_user_passlist,
		"-f",
		"-u",
		current_service.target, 
		"-s", 
		current_service.port, 
		"ssh",
	}
	hydra_scan := createOSServiceScan(
		current_service, 
		"hydra-ssh-brute", 
		"hydra", 
		hydra_args,
	)
	service_scan_list = append(service_scan_list, hydra_scan)
	return service_scan_list
}

func addTelnetScansToList(service_scan_list []scan, current_service *service) []scan {
	banner_grab_args := []string{
		"-nvv",
		current_service.target,
		current_service.port,
	}
	banner_grab_scan := createOSServiceScan(
		current_service,
		"telnet-banner",
		"nc",
		banner_grab_args,
	)
	service_scan_list = append(service_scan_list, banner_grab_scan)
	return service_scan_list
}

func addSMTPScansToList(service_scan_list []scan, current_service *service) []scan {
	full_smtp_enum_script_path := filepath.Join(script_dir, "smtp-user-enum.pl")
	smtp_user_enum_scan_args := []string{
		"-U", 
		smtp_default_namelist, 
		"-t", 
		current_service.target, 
		"-p", 
		current_service.port,
	}
	smtp_user_enum_scan := createOSServiceScan(
		current_service,
		"smtp-user-enum", 
		full_smtp_enum_script_path, 
		smtp_user_enum_scan_args,
	)
	// https://github.com/xapax/oscp/blob/master/recon_enum/reconscan.py
	smtp_nmap_scan_args := []string{
		"-sV", 
		"-Pn", 
		"-p", 
		current_service.port, 
		"--script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,s" +
		"mtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-brute,smtp-nt" +
		"lm-info,smtp-open-relay",
		current_service.target,
	}
	smtp_nmap_scan := createOSServiceScan(
		current_service,
		"smtp-nmap-enum",
		"nmap",
		smtp_nmap_scan_args,
	)
	service_scan_list = append(service_scan_list, smtp_user_enum_scan)
	service_scan_list = append(service_scan_list, smtp_nmap_scan)
	return service_scan_list
}

func addSNMPScansToList(service_scan_list []scan, current_service *service) []scan {
	nmap_snmp_args := []string{
		"-sV",
		"-Pn",
		"-vv",
		"-p",
		current_service.port,
		"--script=snmp-netstat,snmp-processes,snmp-brute,snmp-info," +
		"snmp-interfaces,snmp-sysdescr,snmp-win32-services,snmp-win32-shares," +
		"snmp-win32-software,snmp-win32-users,snmp-ios-config,snmp-hh3c-logins",
	}
	nmap_snmp_scan := createOSServiceScan(
		current_service,
		"snpm-nmap-enum",
		"nmap",
		nmap_snmp_args,
	)
	onesixtyone_scan := createOSServiceScan(
		current_service,
		"snmp-161-enum",
		"onesixtyone",
		[]string{current_service.target},
	)
	snmpwalk_args := []string{
		"-c",
		"public",
		"v1",
		current_service.target,
	}
	snmpwalk_scan := createOSServiceScan(
		current_service,
		"snmpwalk-scan",
		"snmpwalk",
		snmpwalk_args,
	)
	service_scan_list = append(service_scan_list, nmap_snmp_scan)
	service_scan_list = append(service_scan_list, onesixtyone_scan)
	service_scan_list = append(service_scan_list, snmpwalk_scan)
	return service_scan_list
}

func addHTTPScansToList(service_scan_list []scan, current_service *service) []scan {
	// dynamically alter prefix to either http or https
	url_target := fmt.Sprintf("http://%v", current_service.target)
	
	// if it's an https service, change the url_target to prepend 
	// https instead of http
	if strings.Contains(current_service.name, "https") || 
	current_service.name == "ssl/http" {
		url_target = fmt.Sprintf("https://%v", current_service.target)
		
		// add sslscan scan
		sslscan_arg := fmt.Sprintf("%v:%v", url_target, current_service.port)
		sslscan_scan := createOSServiceScan(
			current_service,
			"sslscan-scan",
			"sslscan",
			[]string{sslscan_arg},
		)
		service_scan_list = append(service_scan_list, sslscan_scan)
	}
	gobuster_dir_args := []string{
		"-u", 
		url_target, 
		"-w", 
		gobuster_default_dirlist,
	}
	gobuster_dir_scan := createOSServiceScan(
		current_service,
		"gobuster-dir-enum", 
		"gobuster", 
		gobuster_dir_args,
	)
	gobuster_cgi_args := []string{
		"-u", 
		url_target, 
		"-w", 
		gobuster_default_cgilist,
	}
	gobuster_cgi_scan := createOSServiceScan(
		current_service,
		"gobuster-dir-enum", 
		"gobuster", 
		gobuster_cgi_args,
	)
	nikto_scan := createOSServiceScan(
		current_service,
		"nikto-scan",
		"nikto",
		[]string{"-h", url_target},
	)
	http_nmap_scan_args := []string{
		"-sV", 
		"-Pn", 
		"vv", 
		"-p", 
		current_service.port, 
		"--script=http-vhosts,http-userdir-enum,http-apache-negotiation," +
		"http-backup-finder,http-config-backup,http-default-accounts,htt" +
		"p-methods,http-method-tamper,http-passwd,http-robots.txt,http-d" +
		"evframework,http-enum,http-frontpage-login,http-git,http-iis-we" +
		"bdav-vuln,http-php-version,http-robots.txt,http-shellshock,http" +
		"-vuln-cve2015-1635", 
		current_service.target,
	}
	http_nmap_scan := createOSServiceScan(
		current_service,
		"http-nmap-scan",
		"nmap",
		http_nmap_scan_args,
	)
	http_curl_scan_args := []string{"-I", url_target}
	http_curl_scan := createOSServiceScan(
		current_service,
		"http-curl-scan",
		"curl",
		http_curl_scan_args,
	)
	robots_txt_scan_target := fmt.Sprintf("%v/robots.txt", url_target)
	robots_txt_scan := createOSServiceScan(
		current_service,
		"robots-txt-scan",
		"curl",
		[]string{robots_txt_scan_target},
	)
	service_scan_list = append(service_scan_list, gobuster_dir_scan)
	service_scan_list = append(service_scan_list, gobuster_cgi_scan)
	service_scan_list = append(service_scan_list, nikto_scan)
	service_scan_list = append(service_scan_list, http_nmap_scan)
	service_scan_list = append(service_scan_list, http_curl_scan)
	service_scan_list = append(service_scan_list, robots_txt_scan)
	return service_scan_list
}

func addSMBScansToList(service_scan_list []scan, current_service *service) []scan {
	ports_arg := fmt.Sprintf("139,%v", current_service.port)
	smb_nmap_vuln_scan_args := []string{
		"-p", 
		ports_arg, 
		"--script=smb-vuln-*",
		"--scriptargs=unsafe=1",
		current_service.target,
	}
	smb_nmap_vuln_scan := createOSServiceScan(
		current_service,
		"smb-nmap-vuln",
		"nmap",
		smb_nmap_vuln_scan_args,
	)
	smb_nmap_enum_scan_args := []string{
		"-p", 
		current_service.port, 
		"--script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-o" +
		"s-discovery,smb-security-mode", 
		current_service.target,
	}
	smb_nmap_enum_scan := createOSServiceScan(
		current_service,
		"smb-nmap-enum",
		"nmap",
		smb_nmap_enum_scan_args,
	)
	smb_enumlinux_scan_args := []string{"-a", current_service.target}
	smb_enumlinux_scan := createOSServiceScan(
		current_service,
		"smb-enumlinux-scan",
		"enum4linux",
		smb_enumlinux_scan_args,
	)
	service_scan_list = append(service_scan_list, smb_nmap_vuln_scan)
	service_scan_list = append(service_scan_list, smb_nmap_enum_scan)
	service_scan_list = append(service_scan_list, smb_enumlinux_scan)
	return service_scan_list
}

func addMSSQLScansToList(service_scan_list []scan, current_service *service) []scan {
	mssql_nmap_script_args := fmt.Sprintf("--script-args=mssql.instance-port=%v,smsql.username-sa,mssql.password-sa", current_service.port)
	mssql_nmap_scan_args := []string{
		"-sV", 
		"-Pn", 
		"-p", 
		current_service.port, 
		"--script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes", 
		mssql_nmap_script_args, 
		current_service.target,
	}
	mssql_nmap_scan := createOSServiceScan(
		current_service,
		"mssql-nmap-scan",
		"nmap",
		mssql_nmap_scan_args,
	)
	service_scan_list = append(service_scan_list, mssql_nmap_scan)
	return service_scan_list
}

func addRDPScansToList(service_scan_list []scan, current_service *service) []scan {
	rdp_scan_args := []string{
		"-l", 
		"administrator", 
		"-P", 
		hydra_default_user_passlist,
		"-f",
		"-u",
		current_service.target, 
		"-s", 
		current_service.port, 
		"rdp",
	}
	rdp_scan := createOSServiceScan(
		current_service,
		"hydra-rdp-brute",
		"hydra",
		rdp_scan_args,
	)
	service_scan_list = append(service_scan_list, rdp_scan)
	return service_scan_list
}

// TODO: transforms a list of services into a list of scans
// converts services identified by nmap output into `scan` structs for
// downstream processing.
func makeServiceScanList(service_list []service) []scan {
	/*
	services covered by reconscan.py:
		[x] ssh
		[x] smtp
		[ ] snmp
		[ ] domain
		[x] ftp
		[x] http/s
		[x] microsoft-ds
		[x] ms-sql
	*/
	service_scan_list := []scan{}
	for i := 0; i < len(service_list); i++ {
		current_service := &service_list[i]
		// set up scans for identified services
		if current_service.name == "ftp" {
			service_scan_list = addFTPScansToList(service_scan_list, current_service)
		} else if current_service.name == "ssh" {
			service_scan_list = addSSHScansToList(service_scan_list, current_service)
		} else if current_service.name == "telnet" {
			service_scan_list = addTelnetScansToList(service_scan_list, current_service)
		} else if current_service.name == "smtp" {
			service_scan_list = addSMTPScansToList(service_scan_list, current_service)
		} else if current_service.name == "snmp" {
			service_scan_list = addSNMPScansToList(service_scan_list, current_service)
		} else if current_service.name == "domain" {
			// add domain scans here
		} else if current_service.name == "http" || current_service.name == "ssl/http" || 
		strings.Contains(current_service.name, "https") {	
			service_scan_list = addHTTPScansToList(service_scan_list, current_service)
		} else if current_service.name == "microsoft-ds" {
			service_scan_list = addSMBScansToList(service_scan_list, current_service)
		} else if current_service.name == "ms-sql" {
			service_scan_list = addMSSQLScansToList(service_scan_list, current_service)
		} else if current_service.name == "msdrdp" || current_service.name == "ms-wbt-server" {
			service_scan_list = addRDPScansToList(service_scan_list, current_service)
		}
	}
	return service_scan_list
}

func main() {
	// initialize the scans so we can clean them up on exit Ctl-C
	var scans []scan

	// sig-term handler
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup(scans)
		os.Exit(1)
	}()

	// get home download dir for logging
	usr, _ := user.Current()
	dir := usr.HomeDir
	default_log_dir := filepath.Join(dir, "Downloads")

	// parse out the flags passed
	target		:= flag.String("target", "d34db33f", "IP address of target machine")
	tentacles 	:= flag.Int("tentacles", 0, "number of AWS 'tentacles' (default=0)")
	output_path	:= flag.String("logfile", default_log_dir, "location of output log file")
	testing		:= flag.Bool("testing", false, "use test executables for enum output")
	flag.Parse()

	// set up the log file path
	time_string := fmt.Sprintf("%v", scan_start.Format(time.RFC3339))
	cuttletarget_dir := fmt.Sprintf("%v-cuttlefish-enum/%v", *target, time_string)
	logfile_root_path = filepath.Join(*output_path, cuttletarget_dir)
	logfile_name := fmt.Sprintf("%v-cuttlemain.cuttlelog", *target)
	logfile_path = filepath.Join(logfile_root_path, logfile_name)

	// create the file directory if we are logging
	if logging {
		err := os.MkdirAll(logfile_root_path, os.ModePerm)
		if err != nil {
			error_mes := fmt.Sprintf("[!] could not create logging path (%v)..disabling logging", logfile_root_path)
			colorPrint(error_mes, string_format.red, false, true)
			error_str := fmt.Sprintf("error: %v", err)
			colorPrint(error_str, string_format.red, false, true)
			logging = false
		}
	}

	// clear the terminal
	print("\033[H\033[2J")

	// header strings
	cuttle_header_1 := "-------------.__   ,+-.           ,+ ~.     ,-----------"
	cuttle_header_2 := "           O  o `- o ,-`           `.o `._./            "
	cuttle_header_3 := "o   O   o   o _O  o /   cuttlefish   \\ O  o    O   o   O"
	cuttle_header_4 := "__o___O____,-`  `\\_*         v0.0     \\._____o___coastal"
	cuttle_header_5 := "[~] supports: ssh, smtp, ftp, http, https, smb, ms-sql"
	colorPrint(cuttle_header_1, string_format.blue,logging, true)
	colorPrint(cuttle_header_2, string_format.blue,logging, true)
	colorPrint(cuttle_header_3, string_format.blue,logging, true)
	colorPrint(cuttle_header_4, string_format.blue,logging, true)
	colorPrint(cuttle_header_5, string_format.blue,logging, true)
	if *testing {
		colorPrint("[*] running in test mode", string_format.yellow, logging, true)
	}
	// var aws_session *session.Session
	if *target == "d34db33f" {
		colorPrint("[!] specify a target with '-target=TARGET_IP'", string_format.red, logging, true)
		os.Exit(0)
	}
	if *tentacles > 0 {
		colorPrint("[!] aws tentacles are not implemented", string_format.red, logging, true)
		os.Exit(0)
	}
	// runmode summary
	opt_1 := fmt.Sprintf("[*] run options")
	logfile_path_string := fmt.Sprintf("\t[*] logging to %v", logfile_root_path)
	opt_2 := fmt.Sprintf("\t[*] target:\t\t%v", *target)
	regularPrint(opt_1, logging, true)
	if logging {
		regularPrint(logfile_path_string, logging, true)
	}
	regularPrint(opt_2, logging, true)

	// if testing, set the os to use the CWD as an executable path
	if *testing {		
		current_path := os.Getenv("PATH")
		current_location,_ := filepath.Abs(filepath.Dir(os.Args[0]))
		if !strings.Contains(current_path, current_location) {
			colorPrint("[!] testing requires preceeding PATH with the cuttlefish dir", string_format.red, logging, true)
			colorPrint("\t[*] alter the PATH variable so that cuttlefish dir has priority", string_format.red, logging, true)
			colorPrint("\t[*] command: `export PATH=$(pwd)/fakebins:$PATH`", string_format.red, logging, true)
			os.Exit(0)
		}
	} else {
		// remove the cuttlefish dir from path to avoid taking precedence over
		// the real binaries
		current_path := os.Getenv("PATH")
		current_location,_ := filepath.Abs(filepath.Dir(os.Args[0]))
		fakebins_location := fmt.Sprintf("%v/fakebins", current_location)
		if strings.Contains(current_path, current_location) {
			fixed_path := strings.Replace(current_path, fakebins_location, "", 5)
			fix_command := fmt.Sprintf("\t[*] command 2: `export PATH=%v`", fixed_path)
			colorPrint("[!] fix PATH to remove cuttlefish dir", string_format.red, logging, true)
			regularPrint("\t[*] command 1: `echo $PATH`", logging, true)
			regularPrint(fix_command, logging, true)
			os.Exit(0)
		}
	}
	
	spoof_service := &service{"all", *target, "all", "all"}
	nmap_tcp_scan := createOSServiceScan(spoof_service, "nmap-tcp-recon", "nmap", []string{})
	nmap_udp_scan := createOSServiceScan(spoof_service, "nmap-udp-recon", "nmap", []string{})
	if os.Getuid() == 0 {
		getuid_string := fmt.Sprintf("[+] root privs enabled (GUID: %v), script scanning with nmap", os.Getuid())
		colorPrint(getuid_string, string_format.green, logging, true)
		nmap_tcp_scan.args = []string{"-vv", "-Pn", "-A", "-sC", "-sS", "-p-", *target}
		nmap_udp_scan.args = []string{"-vv", "-Pn", "-A", "-sC", "-sU", "--top-ports", "200"}
		scans = append(scans, nmap_tcp_scan)
		scans = append(scans, nmap_udp_scan)
	} else {
		getuid_string := fmt.Sprintf("[!] not executed as root (GUID: %v), script scanning not performed", os.Getuid())
		colorPrint(getuid_string, string_format.yellow, logging, true)
		nmap_tcp_scan.args = []string{"-vv", "-Pn", "-A", "-p-", *target}
		//nmap_tcp_scan.args = []string{*target}
		// don't bother with UDP since we can't w/o root
		scans = append(scans, nmap_tcp_scan)
	}

	// setup the scan channel
	recon_scan_channel := make(chan bool)
	
	// pass by reference so we update the shared struct value
	colorPrint("[*] starting intial nmap recon scan", string_format.blue,logging, true)
	for i := 0; i < len(scans); i++ {
		go performScan(*target, &scans[i])
	}
	go scanProgress(scans, *target, recon_scan_channel)
	// block on recon scan channel 
	<-recon_scan_channel
	
	// now let's find services from the recon scan results
	identified_services := identifyServices(scans[0].results, *target)
	if os.Getuid() == 0 {
		identified_udp_services := identifyServices(scans[1].results, *target)
		identified_services := append(identified_services, identified_udp_services...)
		identified_services = removeDuplicateServices(identified_services)
	}
	if len(identified_services) == 0 {
		colorPrint("[-] no services identified", string_format.red, logging, true)
		colorPrint("\t[!] try different scan options", string_format.yellow, logging, true)
		os.Exit(0)
	}
	colorPrint("[+] identified running services", string_format.blue, logging, true)
	for i := 0; i < len(identified_services); i++ {
		if identified_services[i].status == "open" {
			service_string := fmt.Sprintf("\t[+] %v (%v)", 
			identified_services[i].name,
			identified_services[i].port)
			colorPrint(service_string, string_format.green, logging, true)
		} else {
			service_string := fmt.Sprintf("\t[-] %v (%v)", 
			identified_services[i].name,
			identified_services[i].port)
			colorPrint(service_string, string_format.red, logging, true)
		}
	}
	colorPrint("[*] starting follow up scans on identified services", string_format.blue, logging, true)
	// start new scans based on the service info
	scans = makeServiceScanList(identified_services)
	service_scan_channel := make(chan bool)
	for i := 0; i < len(scans); i++ {
		go performScan(*target, &scans[i])
	}
	go scanProgress(scans, *target, service_scan_channel)
	<-service_scan_channel

	// process the post-scan results and perform any subsequent analysis
	// or further enum/discovery
	for i := 0; i < len(scans); i++ {
		postScanProcessing(scans[i])
	}
	total_scan_time := time.Now().Sub(scan_start).Minutes()
	total_scan_print := fmt.Sprintf("%.2f mins", total_scan_time)
	complete_string := fmt.Sprintf("[+] cuttlefish enumeration of %v complete! (%v)%v", *target, total_scan_print, string_format.end)
	regularPrint(complete_string, logging, true)
}









