package gcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/doitintl/secrets-consumer-env/pkg/vault"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	secretspb "google.golang.org/genproto/googleapis/cloud/secrets/v1beta1"

	gax "github.com/googleapis/gax-go/v2"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Config - configuration for GCP
type Config struct {
	ProjectID                    string
	SecretName                   string
	SecretVersion                string
	GoogleApplicationCredentials string
	ServiceAccount               string
	UseInTests                   bool
}

// SecretManagerAccessRequestParams is used as input to access a secret from Secret Manager.
type SecretManagerAccessRequestParams struct {
	// Project is the ID or number of the project from which to access secrets.
	Project string

	// Name is the name of the secret to access.
	Name string

	// Version is the version of the secret to access.
	Version string
}

// SecretManagerClient interface
type SecretManagerClient interface {
	AccessSecretVersion(ctx context.Context, req *secretspb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretspb.AccessSecretVersionResponse, error)
}

// GetSecretData will fetch the secret from secret manager
func GetSecretData(client SecretManagerClient, accessRequest *secretspb.AccessSecretVersionRequest) (*secretspb.SecretPayload, error) {
	ctx := context.Background()
	resp, err := client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		terr, ok := grpcstatus.FromError(err)
		if ok && terr.Code() == grpccodes.NotFound {
			return nil, fmt.Errorf("secret not found %v", err)
		}
		return nil, fmt.Errorf("failed to access secret: %v", err)
	}
	return resp.Payload, nil
}

// ExtractPayload decode JSON respose from secret data
func ExtractPayload(payload secretspb.SecretPayload) (map[string]interface{}, error) {
	var secretData map[string]interface{}
	err := json.Unmarshal(payload.Data, &secretData)
	if err != nil {
		return nil, fmt.Errorf("bad secret JSON data, can not decode secret JSON data %v", err)
	}
	return secretData, nil
}

// NewSecretManagerClient create new secret manager client
func NewSecretManagerClient() (*secretmanager.Client, error) {
	log.Info("Creating new GCP Secret Manager client")
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating secret manager client %v", err)
	}
	return client, nil
}

// BuildAccessSecretRequest from params
func BuildAccessSecretRequest(s *SecretManagerAccessRequestParams) (*secretspb.AccessSecretVersionRequest, error) {
	accessRequest := &secretspb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s", s.Project, s.Name, s.Version),
	}
	return accessRequest, nil

}

// RetrieveSecret Initialize client and get secret data
func RetrieveSecret(client SecretManagerClient, cfg *Config) (map[string]interface{}, error) {
	var (
		logger *log.Entry
		err    error
	)

	if !cfg.UseInTests {
		sa, err := vault.GetServiceAccountCreds(&vault.GCPBackendConfig{Project: cfg.ProjectID, CredsPath: cfg.GoogleApplicationCredentials})
		if err != nil {
			return nil, err
		}
		cfg.ServiceAccount = sa.Email
	}

	logger = log.WithFields(logrus.Fields{
		"project":         cfg.ProjectID,
		"secret_name":     cfg.SecretName,
		"secret_version":  cfg.SecretVersion,
		"service_account": cfg.ServiceAccount,
	})

	logger.Info("Getting secrets from GCP Secret Manager")
	params := &SecretManagerAccessRequestParams{
		Project: cfg.ProjectID,
		Name:    cfg.SecretName,
		Version: cfg.SecretVersion,
	}

	accessRequest, err := BuildAccessSecretRequest(params)
	if err != nil {
		return nil, err
	}
	payload, err := GetSecretData(client, accessRequest)
	if err != nil {
		return nil, err
	}
	secretData, err := ExtractPayload(*payload)
	if err != nil {
		return nil, err
	}
	return secretData, nil
}
