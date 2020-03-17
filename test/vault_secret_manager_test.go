package test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	vaultapi "github.com/hashicorp/vault/api"
	vaultSecretsManager "github.com/innovia/secrets-consumer-env/vault"
)

type mockVaultClient struct {
	config *vaultSecretsManager.Config
	secret *vaultapi.Secret
}

func (m *mockVaultClient) Read(path string) (*vaultapi.Secret, error) {
	var secretData map[string]interface{}

	switch path {
	case "data/some/secret/path/API_KEY":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "top-secret"}
		} else {
			secretData = map[string]interface{}{"KEY": "top-secret"}
		}
	case "data/some/secret/path/DATABASE_URL":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "some.mysql.host:3306"}
		} else {
			secretData = map[string]interface{}{"HOST": "some.mysql.host:3306"}
		}
	case "data/some/secret/path/DB_PASSWORD":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "pa33w0rd123"}
		} else {
			secretData = map[string]interface{}{"PASSWORD": "pa33w0rd123"}
		}
	case "/some/secret/path":
		secretData = map[string]interface{}{"API_KEY": "plain-text-123"}
	case "/some/secret/path/API_KEY":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "top-secret"}
		} else {
			secretData = map[string]interface{}{"KEY": "top-secret"}
		}
	case "/some/secret/path/DATABASE_URL":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "some.mysql.host:3306"}
		} else {
			secretData = map[string]interface{}{"HOST": "some.mysql.host:3306"}
		}
	case "/some/secret/path/DB_PASSWORD":
		if m.config.UseSecretNamesAsKeys {
			secretData = map[string]interface{}{"value": "pa33w0rd123"}
		} else {
			secretData = map[string]interface{}{"PASSWORD": "pa33w0rd123"}
		}
	}

	return &vaultapi.Secret{Data: secretData}, nil
}

func (m *mockVaultClient) List(path string) (*vaultapi.Secret, error) {
	return &vaultapi.Secret{
		Data: map[string]interface{}{
			"keys": []string{"API_KEY", "DATABASE_URL", "DB_PASSWORD", "secret_v2/"},
		},
	}, nil
}

func getSecret(t *testing.T, client *mockVaultClient, cfg *vaultSecretsManager.Config) (map[string]interface{}, error) {
	secretData, err := vaultSecretsManager.RetrieveSecret(client, cfg)
	if err != nil {
		t.Fatalf("error retrieving secret data %v", err)
	}
	return secretData, nil
}

func TestVaultGetSecretData(t *testing.T) {
	testCases := []struct {
		name     string
		client   *mockVaultClient
		function func(*testing.T, *mockVaultClient, *vaultSecretsManager.Config) (map[string]interface{}, error)
		wants    map[string]interface{}
	}{
		{
			name: "get plain secret path read v1",
			client: &mockVaultClient{
				config: &vaultSecretsManager.Config{
					Path:                 "/some/secret/path",
					UseSecretNamesAsKeys: false,
					IsKVv2:               false,
				},
			},
			function: getSecret,
			wants:    map[string]interface{}{"API_KEY": "plain-text-123"},
		}, {
			name: "get multiple secrets from path ending with a /",
			client: &mockVaultClient{
				config: &vaultSecretsManager.Config{
					Path:                 "/some/secret/path/",
					UseSecretNamesAsKeys: false,
					IsKVv2:               false,
				},
			},
			function: getSecret,
			wants: map[string]interface{}{
				"KEY":      "top-secret",
				"HOST":     "some.mysql.host:3306",
				"PASSWORD": "pa33w0rd123",
			},
		}, {
			name: "get keys from path ending with a / with their secret value",
			client: &mockVaultClient{
				config: &vaultSecretsManager.Config{
					Path:                 "/some/secret/path/",
					UseSecretNamesAsKeys: false,
					IsKVv2:               true,
				},
			},
			function: getSecret,
			wants: map[string]interface{}{
				"KEY":      "top-secret",
				"HOST":     "some.mysql.host:3306",
				"PASSWORD": "pa33w0rd123",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secretData, err := testCase.function(t, testCase.client, testCase.client.config)
			if err != nil {
				t.Fatalf("error runing test %s, %v", testCase.name, err)
			}
			if !cmp.Equal(secretData, testCase.wants) {
				t.Errorf("secretData = diff %v", cmp.Diff(secretData, testCase.wants))
			}
		})
	}
}
