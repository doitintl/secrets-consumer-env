// This script expect basic vault env vars to exist before execution
// a new set of env vars (sanitizedEnviron) is then made to hole only the env appears in the secret

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// SecretManagerClient interface
type SecretManagerClient interface {
	Read(path string) (*vaultapi.Secret, error)
	List(path string) (*vaultapi.Secret, error)
}

// CastSecretDataToStringMap convert the secret data to map[string]interface{}
func CastSecretDataToStringMap(secretData map[string]interface{}) map[string]interface{} {
	var data map[string]interface{}

	v2Data, ok := secretData["data"]

	if ok {
		data = cast.ToStringMap(v2Data)
	} else {
		data = cast.ToStringMap(secretData)
	}

	return data
}

// ConfigureGCPAccess configure GCP parameters for vault
func ConfigureGCPAccess() (*GCPBackendConfig, error) {
	var gcpCfg *GCPBackendConfig
	var logger *log.Entry
	var err error

	gcpCfg = &GCPBackendConfig{
		project:        os.Getenv("PROJECT_ID"),
		credsPath:      os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		serviceAccount: "",
	}
	if gcpCfg.project == "" {
		return nil, fmt.Errorf("PROJECT_ID environment variable is missing")
	}

	if gcpCfg.credsPath == "" {
		return nil, errors.New(
			"CREDS_PATH environment variable is missing, please specify the file path to the GCP service account JSON file",
		)
	}

	gcpCfg.credsPath, err = filepath.Abs(gcpCfg.credsPath)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to find the full path for CREDS_PATH %s, %w",
			gcpCfg.credsPath,
			err,
		)
	}

	logger = log.WithFields(logrus.Fields{
		"project":        gcpCfg.project,
		"serviceAccount": gcpCfg.serviceAccount,
	})
	logger.Info("Vault access secret data using GCP Backend")
	return gcpCfg, nil
}

// ConfigureVaultAccess configure Vault parameters
func ConfigureVaultAccess() (*Config, error) {
	useSecretNamesAsKeys, _ := strconv.ParseBool(os.Getenv("VAULT_USE_SECRET_NAMES_AS_KEYS"))
	vaultCfg := &Config{
		Role:                 os.Getenv("VAULT_ROLE"),
		Path:                 os.Getenv("VAULT_PATH"),
		TokenPath:            os.Getenv("TOKEN_PATH"),
		Backend:              os.Getenv("VAULT_BACKEND"),
		UseSecretNamesAsKeys: useSecretNamesAsKeys,
	}

	if vaultCfg.Role == "" {
		return nil, fmt.Errorf("VAULT_ROLE environment variables is missing")
	}

	if vaultCfg.Path == "" {
		return nil, fmt.Errorf("VAULT_PATH environment variables is missing")
	}

	return vaultCfg, nil
}

func readSecret(client SecretManagerClient, secretPath string) (*vaultapi.Secret, error) {
	log.Infof("Getting Vault secrets from path: %s", secretPath)
	secret, secretError := client.Read(secretPath)
	if secretError != nil {
		return nil, fmt.Errorf("failed to read secret '%s' %v", secretPath, secretError)
	}
	if secret.Data == nil {
		return nil, fmt.Errorf("Vault secret path not found %s", secretPath)
	}
	return secret, nil
}

func listKeys(client SecretManagerClient, cfg Config) ([]string, error) {
	path := cfg.Path
	var err error
	log.Infof("secret path ends with a \"/\" or has \"*\", listing keys from path: %s", path)

	if cfg.IsKVv2 {
		path = addPrefixToVKVPath(path, cfg.MountPath, "metadata")
		if err != nil {
			return nil, fmt.Errorf("could not add prefix metadata to secret path: %v", err)
		}
	}

	data, err := client.List(path)
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %v", err)
	}

	if data == nil {
		return nil, fmt.Errorf("no value found at: %s, check the path", path)
	}
	keys := cast.ToStringSlice(data.Data["keys"])
	return keys, nil
}

func setSecretPath(cfg *Config, secretPath string) string {
	var path string
	if cfg.IsKVv2 {
		path = addPrefixToVKVPath(secretPath, cfg.MountPath, "data")
	} else {
		path = secretPath
	}
	return path
}

// RetrieveSecret retrieve secrets from vault
func RetrieveSecret(client SecretManagerClient, cfg *Config) (map[string]interface{}, error) {
	/*
		list of secrets names (keys) /secret/kv2/service/
		USE_SECRET_NAME_AS_KEY
		ABC
		|- value: 123
		DEF
		|- value: 456
		XYZ
		|- value: 999

		in this case we need the secret name to be the key, and the value to be the value

		or it can be a list of secrets with multiple key values
		secrets/secret_v2/secret/secret_v2/service
		test1
		|- ABC 123
		|- DEF xyz
		test2
		|- SOME_SECRET 123
		|- AAA: 111


		in this case we need the secret keys and values
	*/
	var keys []string
	secretData := make(map[string]interface{})
	var err error

	log.Info("Using Vault Secrets")

	if strings.HasSuffix(cfg.Path, "/") || strings.Contains(cfg.Path, "*") || strings.Contains(cfg.Path, "metadata") {
		keys, err = listKeys(client, *cfg)
		if err != nil {
			return nil, err
		}

		log.Infof("keys: %+v\n", keys)
		if len(keys) == 0 {
			return nil, fmt.Errorf("could not list keys under path: %s", cfg.Path)
		}
		if cfg.UseSecretNamesAsKeys {
			log.Info("Using secret names as keys")
		} else {
			log.Info("Using secret keys and values")
		}
		// get the secrets data from the keys
		for _, key := range keys {
			// ignore subtrees
			if strings.HasSuffix(key, "/") {
				log.Warnf("key %s is a subtree - ignoring it", key)
				continue
			}
			var value interface{}
			secretKeyPath := fmt.Sprintf("%s%s", cfg.Path, key)
			path := setSecretPath(cfg, secretKeyPath)
			secret, err := readSecret(client, path)
			if err != nil {
				return nil, err
			}

			data := CastSecretDataToStringMap(secret.Data)
			// if keys are single value get the value
			// secret/path/api_key
			// value: "top-secret"
			if cfg.UseSecretNamesAsKeys {
				for _, v := range data {
					value = v
				}
				secretData[key] = value
				// else get every key, value in secret
			} else {
				for name, value := range data {
					secretData[name] = value
				}
			}
		}
	}

	if len(secretData) != 0 {
		return secretData, nil
	}

	path := setSecretPath(cfg, cfg.Path)
	secret, err := readSecret(client, path)

	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}
