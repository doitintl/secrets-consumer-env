package test

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/magiconair/properties/assert"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	awsSecretsManager "github.com/doitintl/secrets-consumer-env/aws"
)

type mockAWSSecretManagerClient struct {
	secretsmanageriface.SecretsManagerAPI
	secretData *secretsmanager.GetSecretValueOutput
}

func (m *mockAWSSecretManagerClient) GetSecretValueWithContext(ctx aws.Context, secretValueInput *secretsmanager.GetSecretValueInput, options ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {
	m.secretData.VersionStages = []*string{secretValueInput.VersionStage}
	if aws.StringValue(secretValueInput.VersionStage) == "AWSCURRENT" {
		m.secretData.SecretString = aws.String(`{"API_KEY": "new123def"}`)
	}
	if aws.StringValue(secretValueInput.VersionStage) == "AWSPREVIOUS" {
		m.secretData.SecretString = aws.String(`{"API_KEY": "old123abc"}`)
	}
	return m.secretData, nil
}

func TestAWSGetSecretData(t *testing.T) {
	mockAwsSecretManager := &mockAWSSecretManagerClient{
		secretData: &secretsmanager.GetSecretValueOutput{
			SecretString:  nil,
			VersionStages: nil,
		},
	}

	secretValueInput := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String("test-secret"),
		VersionStage: aws.String("AWSCURRENT"),
	}

	secretData, err := awsSecretsManager.GetSecretData(mockAwsSecretManager, secretValueInput)
	if err != nil {
		t.Fatalf("error getting secret data: %v", err)
	}
	assert.Equal(t, secretData["API_KEY"], "new123def")
}

func TestAWSGetSecretPreviousVersion(t *testing.T) {
	mockAwsSecretManager := &mockAWSSecretManagerClient{
		secretData: &secretsmanager.GetSecretValueOutput{
			SecretString:  aws.String("test-secret"),
			VersionStages: []*string{aws.String("AWSPREVIOUS")},
		},
	}
	secretValueInput := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String("test-secret"),
		VersionStage: aws.String("AWSPREVIOUS"),
	}
	secretData, err := awsSecretsManager.GetSecretData(mockAwsSecretManager, secretValueInput)
	if err != nil {
		t.Fatalf("error getting secret data: %v", err)
	}
	assert.Equal(t, secretData["API_KEY"], "old123abc")
}
