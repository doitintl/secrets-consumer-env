package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	log "github.com/sirupsen/logrus"
)

func newSecretManagerClient(region, roleArn string) *secretsmanager.SecretsManager {
	if region == "" {
		region = "us-east-1"
	}
	log.Infof("Using region: %s", region)
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region), // Sessions Manager functions require region configuration
	}))

	if roleArn != "" {
		log.Infof("Using Role Arn: %s", roleArn)
		// the new Credentials object wraps the AssumeRoleProvider
		sess.Config.Credentials = stscreds.NewCredentials(sess, roleArn)
	}

	// Create a SecretsManager client with additional configuration
	return secretsmanager.New(sess, aws.NewConfig().WithRegion(region))
}

// GetSecretData will fetch the secret from secret manager
func GetSecretData(api secretsmanageriface.SecretsManagerAPI, secretValueInput *secretsmanager.GetSecretValueInput) (map[string]interface{}, error) {
	var secretData map[string]interface{}
	ctx := context.Background()
	secretValueOutput, err := api.GetSecretValueWithContext(ctx, secretValueInput)

	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	err = json.Unmarshal([]byte(*secretValueOutput.SecretString), &secretData)
	if err != nil {
		return nil, fmt.Errorf("bad secret JSON data, can not decode secret JSON data: %w", err)
	}
	return secretData, nil
}

func buildSecretValueInput() (*secretsmanager.GetSecretValueInput, error) {
	secretName := aws.String(os.Getenv("SECRET_NAME"))
	if aws.StringValue(secretName) == "" {
		return nil, fmt.Errorf("error: missing SECRET_NAME environment variable")
	}
	versionStage := aws.String("AWSCURRENT")
	if os.Getenv("PREVIOUS_VERSION") != "" {
		versionStage = aws.String("AWSPREVIOUS")
	}
	secretValueInput := &secretsmanager.GetSecretValueInput{
		SecretId:     secretName,
		VersionStage: versionStage,
	}
	return secretValueInput, nil
}

// RetrieveSecret from AWS secrets manager
func RetrieveSecret() (map[string]interface{}, error) {
	log.Info("Using AWS Secret Manager")
	region := os.Getenv("REGION")
	roleArn := os.Getenv("ROLE_ARN")
	secretValueInput, err := buildSecretValueInput()
	if err != nil {
		return nil, err
	}

	client := newSecretManagerClient(region, roleArn)
	secretData, err := GetSecretData(client, secretValueInput)
	if err != nil {
		return nil, err
	}
	return secretData, nil
}
