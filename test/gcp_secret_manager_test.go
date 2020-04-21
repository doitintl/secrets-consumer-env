package test

import (
	"context"
	"testing"

	gcpSecretsManager "github.com/doitintl/secrets-consumer-env/pkg/gcp"
	"github.com/googleapis/gax-go/v2"
	"github.com/magiconair/properties/assert"
	secretspb "google.golang.org/genproto/googleapis/cloud/secrets/v1beta1"
)

type mockGCPSecretManagerClient struct{}

func (m *mockGCPSecretManagerClient) AccessSecretVersion(ctx context.Context, req *secretspb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretspb.AccessSecretVersionResponse, error) {
	return &secretspb.AccessSecretVersionResponse{
		Payload: &secretspb.SecretPayload{
			Data: []byte(`{"API_KEY": "top-secret-key-123"}`),
		},
	}, nil
}

func TestGCPGetSecretData(t *testing.T) {
	client := &mockGCPSecretManagerClient{}
	cfg := &gcpSecretsManager.Config{
		ProjectID:  "fake-project",
		SecretName: "top-secret",
	}
	secretData, err := gcpSecretsManager.RetrieveSecret(client, cfg)
	if err != nil {
		t.Fatalf("error retrieving secret data %v", err)
	}
	assert.Equal(t, secretData["API_KEY"], "top-secret-key-123")
}
