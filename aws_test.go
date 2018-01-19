package main

import (
	"testing"
)

func testGetCreds(t *testing.T) {  
    aws_creds := getCreds()
    if len(aws_creds.AccessKey) < 1 || len(aws_creds.SecretKey) < 1 {
       t.Errorf("AWS creds incorrect:\n\tAccessKey: %v\n\tSecretKey: %v\n")
    }
}

func testInitializeAWSSession(t *testing.T) {
	aws_session := initializeAWSSession()
	_, crederr := aws_session.Config.Credentials.Get()
	if crederr != nil {
		t.Error("Incorrectly authenticated AWS session")
	}
}