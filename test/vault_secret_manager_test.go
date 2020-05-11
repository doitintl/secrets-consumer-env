package test

import (
	"testing"

	vaultSecretsManager "github.com/doitintl/secrets-consumer-env/pkg/vault"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"

	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	vaultapi "github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	hashivault "github.com/hashicorp/vault/vault"

	"github.com/prometheus/common/log"
)

type vaultConfigSecret struct {
	path string
	data map[string]interface{}
}

func retrieveSecrets(t *testing.T, client *vaultapi.Client, secretsConfigList []string) (map[string]interface{}, error) {
	vaultCfg, err := vaultSecretsManager.ConfigureVaultSecrets(client, secretsConfigList, &vaultSecretsManager.Config{})

	if err != nil {
		t.Fatalf("error configuring vault secrets %v", err)
	}

	secretData, err := vaultSecretsManager.RetrieveSecrets(client, vaultCfg)
	if err != nil {
		t.Fatal(err)
	}
	return secretData, nil
}

func TestVaultSecrets(t *testing.T) {
	viper.AutomaticEnv()
	realCluster := viper.GetBool("real_cluster")
	var (
		err     error
		client  *vaultapi.Client
		cluster *hashivault.TestCluster
	)

	if realCluster {
		client, err = vaultapi.NewClient(vaultapi.DefaultConfig())
		rootToken := viper.GetString("root_token")
		client.SetToken(rootToken)
		if err != nil {
			t.Fatalf("Error creating Vault client: %v", err)
		}
	} else {
		client, cluster = createVaultTestCluster(t)
		defer cluster.Cleanup()
	}

	testCases := []struct {
		name              string
		secretsConfigList []string
		function          func(*testing.T, *vaultapi.Client, []string) (map[string]interface{}, error)
		wants             map[string]interface{}
	}{
		{
			name: "Plain V1 Secret",
			secretsConfigList: []string{
				`{"path": "secrets/v1/some/secrets/path"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"API_V2":       "extra-v2",
				"api_key":      "app_key",
				"database_url": "127.0.0.1:3306",
				"password":     "secret",
			},
		},
		{
			name: "secret names as keys v1",
			secretsConfigList: []string{
				`{"path": "secrets/v1/multi/secrets/path/", "use-secret-names-as-keys": "true"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"APP_NAME":     "TestApp",
				"api_key":      "top-secret",
				"database_url": "some.mysql.host:3306",
				"password":     "pa33w0rd123",
				"testers":      "choice",
			},
		},
		{
			name: "Plain V2 Secret",
			secretsConfigList: []string{
				`{"path": "secrets/v2/plain/secrets/path/app"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"api_key":      "app_key_v2",
				"database_url": "v2-host:3306",
				"password":     "secrets-v2",
			},
		},
		{
			name: "Plain V2 Secret Access Secret Version 2",
			secretsConfigList: []string{
				`{"path": "secrets/v2/plain/secrets/path/app", "version": "2"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"api_key":      "version-2",
				"database_url": "version-2-host:3306",
				"password":     "version-2-password",
			},
		},
		{
			name: "secret names as keys v2",
			secretsConfigList: []string{
				`{"path": "secrets/v2/multi/secrets/path/", "use-secret-names-as-keys": "true"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"api_key":      "v2-top-secret",
				"database_url": "v2.mysql.host:3306",
				"password":     "v2-pa33w0rd123",
			},
		},
		{
			name: "multiple secrets",
			secretsConfigList: []string{
				`{"path": "secrets/v2/multi/secrets/path/", "use-secret-names-as-keys": "true"}`,
				`{"path": "secrets/v1/multi2/secrets/path/", "use-secret-names-as-keys": "true"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"database_url": "v2.mysql.host:3306",
				"password":     "v2-pa33w0rd123",
				"api_key":      "multi2-secret",
				"db":           "multi2.mysql.host:3306",
				"vault-pass":   "multi2-pa33w0rd123",
			},
		}, {
			name: "multiple secrets v2",
			secretsConfigList: []string{
				`{"path": "secrets/v2/multi2/secrets/path/", "use-secret-names-as-keys": "true"}`,
				`{"path": "secrets/v2/plain/secrets/path/app"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"vault-pass":   "multi2-pa33w0rd123",
				"api_key":      "app_key_v2",
				"database_url": "v2-host:3306",
				"password":     "secrets-v2",
			},
		}, {
			name: "wildcard secrets v2",
			secretsConfigList: []string{
				`{"path": "secrets/v2/plain/secrets/db*"}`,
			},
			function: retrieveSecrets,
			wants: map[string]interface{}{
				"user":     "root",
				"password": "secret-sauce",
				"param1":   "param1-value",
				"param2":   "param2-value",
				"param3":   "param3-value",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secretData, err := testCase.function(t, client, testCase.secretsConfigList)
			if err != nil {
				t.Fatalf("error runing test %s, %v", testCase.name, err)
			}
			if !cmp.Equal(secretData, testCase.wants) {
				t.Logf("wants: %v", testCase.wants)
				t.Logf("got: %v", secretData)
				t.Errorf("secretData = diff %v", cmp.Diff(secretData, testCase.wants))
			}
		})
	}
}

// Setup required secrets, policies, etc.
func seedVaultData(t *testing.T, client *vaultapi.Client) error {
	var err error
	secretsV1 := []vaultConfigSecret{
		{
			path: "secrets/v1/some/secrets/path",
			data: map[string]interface{}{
				"api_key":      "app_key",
				"database_url": "127.0.0.1:3306",
				"password":     "secret",
			},
		}, {
			path: "secrets/v1/multi/secrets/path/api_key",
			data: map[string]interface{}{"value": "top-secret"},
		}, {
			path: "secrets/v1/multi/secrets/path/database_url",
			data: map[string]interface{}{"value": "some.mysql.host:3306"},
		}, {
			path: "secrets/v1/multi/secrets/path/password",
			data: map[string]interface{}{"value": "pa33w0rd123"},
		}, {
			path: "secrets/v1/multi/secrets/path/testers",
			data: map[string]interface{}{"value": "choice"},
		}, {
			path: "secrets/v1/multi2/secrets/path/api_key",
			data: map[string]interface{}{"value": "multi2-secret"},
		}, {
			path: "secrets/v1/multi2/secrets/path/db",
			data: map[string]interface{}{"value": "multi2.mysql.host:3306"},
		}, {
			path: "secrets/v1/multi2/secrets/path/vault-pass",
			data: map[string]interface{}{"value": "multi2-pa33w0rd123"},
		}, {
			path: "secrets/v1/multi2/secrets/path/bool-type",
			data: map[string]interface{}{"value": true},
		}, {
			path: "secrets/v1/multi2/secrets/path/int-type",
			data: map[string]interface{}{"value": 8200},
		},
	}

	secretsV2 := []vaultConfigSecret{
		{
			path: "secrets/v2/data/plain/secrets/path/app",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"api_key":      "next",
					"database_url": "next",
					"password":     "next",
				},
			},
		}, {
			path: "secrets/v2/data/plain/secrets/db_credentials",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"user":     "root",
					"password": "secret-sauce",
				},
			},
		}, {
			path: "secrets/v2/data/plain/secrets/db_params",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"param1": "param1-value",
					"param2": "param2-value",
					"param3": "param3-value",
				},
			},
		}, {
			path: "secrets/v2/data/plain/secrets/path/app",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"api_key":      "version-2",
					"database_url": "version-2-host:3306",
					"password":     "version-2-password",
				},
			},
		}, {
			path: "secrets/v2/data/plain/secrets/path/app",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"api_key":      "app_key_v2",
					"database_url": "v2-host:3306",
					"password":     "secrets-v2",
				},
			},
		}, {
			path: "secrets/v2/data/multi/secrets/path/api_key",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"value": "v2-top-secret",
				},
			},
		}, {
			path: "secrets/v2/data/multi/secrets/path/database_url",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"value": "v2.mysql.host:3306",
				},
			},
		}, {
			path: "secrets/v2/data/multi/secrets/path/password",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"value": "v2-pa33w0rd123",
				},
			},
		}, {
			path: "secrets/v2/data/multi2/secrets/path/api_key",
			data: map[string]interface{}{
				"data": map[string]interface{}{"value": "multi2-secret"},
			},
		}, {
			path: "secrets/v2/data/multi2/secrets/path/database_url",
			data: map[string]interface{}{
				"data": map[string]interface{}{"value": "multi2.mysql.host:3306"},
			},
		}, {
			path: "secrets/v2/data/multi2/secrets/path/vault-pass",
			data: map[string]interface{}{
				"data": map[string]interface{}{"value": "multi2-pa33w0rd123"},
			},
		},
	}

	log.Info("Seeding secrets into Vault")
	for _, secret := range secretsV1 {
		_, err := client.Logical().Write(secret.path, secret.data)
		if err != nil {
			log.Errorf("error seeding secret v1: %v", err)
		}
	}
	for _, secret := range secretsV2 {
		log.Infof("Adding secret %s", secret.path)
		_, err := client.Logical().Write(secret.path, secret.data)
		if err != nil {
			log.Errorf("error seeding secret v2: %v", err)
		}
	}

	if err != nil {
		return err
	}
	return nil
}

func createVaultTestCluster(t *testing.T) (*vaultapi.Client, *hashivault.TestCluster) {
	t.Helper()
	t.Log("Creating Vault Test Cluster in-memory backend")

	coreConfig := &hashivault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
		},
	}

	cluster := hashivault.NewTestCluster(t, coreConfig, &hashivault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	core := cluster.Cores[0]
	hashivault.TestWaitActive(t, core.Core)
	client := core.Client

	// Create KV v1 and v2
	mountInputV1 := &vaultapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"path": "/secrets/v1",
		},
	}

	mountInputV2 := &vaultapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"path":    "/secrets/v2",
			"version": "2",
		},
	}
	mountPath1 := "/secrets/v1"
	mountPath2 := "/secrets/v2"

	log.Info("Creating secrets/v1 kv engine")
	if err := client.Sys().Mount(mountPath1, mountInputV1); err != nil {
		t.Fatal("error creating secrets/v1 mount")
	}

	log.Info("Creating secrets/v2 kv engine")
	if err := client.Sys().Mount(mountPath2, mountInputV2); err != nil {
		t.Fatal("error creating secrets/v2 mount")
	}

	// Setup required secrets, policies, etc.
	err := seedVaultData(t, client)
	if err != nil {
		t.Fatalf("error seeding data: %v", err)
	}

	return client, cluster
}
