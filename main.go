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

func initialize_aws() {
	// load the creds
	
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

}