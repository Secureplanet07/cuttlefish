package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
	/*
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	//*/
)

type creds struct {
	AccessKey string
	SecretKey string
}

// getCreds()
//	pull aws creds from creds.json
func getCreds() creds {
	fmt.Printf("[*] loading aws credentials from ./creds.json\n")
	rawjson, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		fmt.Println("\t[-]", err.Error())
		os.Exit(1)
	}
	var awscreds creds
	err = json.Unmarshal(rawjson, &awscreds)
	if err != nil {
		fmt.Println("\t[-]", err.Error())
		os.Exit(1)
	}
	if len(awscreds.AccessKey) == 0 || len(awscreds.SecretKey) == 0 {
		fmt.Println("\t[-] keys not loaded successfully")
		os.Exit(1)
	}
	fmt.Printf("[+] creds loaded successfully\n")
	fmt.Printf("\taccess_key: %v\n\tsecret_key: %v\n", awscreds.AccessKey, awscreds.SecretKey)
	return awscreds
}

func initializeAWS() {
	// load the creds
	getCreds()
	// configure your aws region
	//sess, err := session.NewSession(&aws.Config{Region: aws.String("us-east-2")})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("[!] please specify a runmode\n")
		fmt.Printf("\t[-] exiting\n")
		os.Exit(1)
	}
	fmt.Printf("[*] welcome to cuttlefish\n")
	initializeAWS()
}





