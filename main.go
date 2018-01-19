package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
	//"github.com/aws/aws-sdk-go/service/ec2"
)

// global structs and vars
type creds struct {
	AccessKey string
	SecretKey string
}

// getCreds()
//	pull aws creds from creds.json
func getCreds() creds {
	fmt.Println("[*] loading aws credentials from ./creds.json")
	var aws_creds creds
	rawjson, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		fmt.Println("\t[-]", err.Error())
		os.Exit(1)
	}
	err = json.Unmarshal(rawjson, &aws_creds)
	if err != nil {
		fmt.Println("\t[-]", err.Error())
		os.Exit(1)
	}
	if len(aws_creds.AccessKey) == 0 || len(aws_creds.SecretKey) == 0 {
		fmt.Println("\t[-] keys not loaded successfully")
		os.Exit(1)
	}
	fmt.Println("\t[+] creds loaded from file successfully")
	return aws_creds
}

func initializeAWSSession() *session.Session{
	// load the creds
	aws_creds := getCreds()
	
	fmt.Println("[*] grabbing AWS session")

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
		fmt.Println("\t[-] invalid credentials", err.Error())
		os.Exit(1)
	}
	fmt.Println("\t[+] successfully authenticated AWS session")
	return sess
}



func main() {
	if len(os.Args) < 2 {
		fmt.Println("[!] please specify a runmode")
		fmt.Println("\t[-] exiting")
		os.Exit(1)
	}
	fmt.Println("[*] welcome to cuttlefish")
	// aws_session := initializeAWSSession()
	initializeAWSSession()

}





