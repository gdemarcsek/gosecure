package secretmanager

import (
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	sm "github.com/aws/aws-sdk-go/service/secretsmanager"
	"strings"
)

// AWSSecretAccessDriver is a secret access driver implementation that uses AWS Secrets Manager to retrieve secrets
type AWSSecretAccessDriver struct {
	StrategyName string
	internal     *sm.SecretsManager
}

type awsSecretLocator struct {
	Name    string
	Key     string
	Version string
}

// New creates a new AWSSecretAccessDriver instance
func New(manager *sm.SecretsManager) *AWSSecretAccessDriver {
	return &AWSSecretAccessDriver{"AWS", manager}
}

func parseLocator(locator string) (awsSecretLocator, error) {
	var result awsSecretLocator

	parts := strings.Split(locator, ".")
	if len(parts) != 3 {
		return result, errors.New("invalid locator string")
	}

	result.Name = parts[0]
	result.Key = parts[1]
	result.Version = parts[2]

	return result
}

// GetSecret returns a given secret based on a string - for the AWS secrets manager implementation it is: "Name.Key.Version"
// The region is selected by the injected SecretsManager service instance
func (a *AWSSecretAccessDriver) GetSecret(locator string) (string, error) {
	query, err := parseLocator(locator)
	if err != nil {
		return "", err
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(query.Name),
		VersionStage: aws.String(query.Version), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := a.internal.GetSecretValue(input)
	if err != nil {
		return "", errors.Wrap(err, "failed to retrieve secret")
	}

	if result.SecretString != nil {
		secretString = *result.SecretString
		jsonMap := make(map[string]interface{})
		err := json.Unmarshal([]byte(secretString), &jsonMap)
		if err != nil {
			return "", errors.Wrap(err, "failed to unmarshal JSON data")
		}
		value, found := jsonMap[query.Key]
		if !found {
			return "", errors.New("key not found")
		}

		return value, nil
	}

	return "", errors.New("binary secrets are not supported")
}
