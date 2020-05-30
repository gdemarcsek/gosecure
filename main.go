package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/gdemarcsek/gosecure/pkg/secretmanager"
	"github.com/gdemarcsek/gosecure/pkg/secretmanager/awssm"
)

func getSecret() (string, error) {
	secretName := "test/gosecure/Service"
	region := "eu-west-2"

	// Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))

	manager, _ := secretmanager.New(awssm.New(svc))
	return manager.GetSecret(fmt.Sprintf("%s.%s.%s", secretName, "RemoteService", "AWSCURRENT"))
}

func main() {
	secret, _ := getSecret()
	fmt.Println(secret)
}
