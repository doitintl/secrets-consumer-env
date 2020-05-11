package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// SecretConfig holds secret config
type SecretConfig struct {
	Path                 string // If Path ends with a / or contains * it will treat it as a wildcard path
	IsKVv2               bool
	MountPath            string
	Version              string // If passed, the value at the version number will be returned
	UseSecretNamesAsKeys bool
}

// Config configuration for Vault
type Config struct {
	Role              string
	TokenPath         string
	Backend           string
	KubernetesBackend string
	SecretsConfigList []SecretConfig
}

// SecretConfigJSON JSON struct for secret config
type SecretConfigJSON struct {
	Path                 string `json:"path"`
	Version              string `json:"version"`
	UseSecretNamesAsKeys string `json:"use-secret-names-as-keys"`
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

// ConfigureVaultSecrets configure Vault Role TokenPath Backend and SecretsConfigList
func ConfigureVaultSecrets(client *api.Client, secretConfigs []string, vaultCfg *Config) (*Config, error) {
	/*
		SecretsConfigs is a slice with a number of struct of secret configuration(Path, isKVv2, mountPath, Version, useSecretKeysAsNames)
		secret config can be consumed in 2 ways

		// --secret-path flags for string path
		// --secret-config flags for json config (version, path, use-secret-names-as-keys)

		either via one annotation or env vars VAULT_PATH, SECRET_VERSION, VAULT_USE_SECRET_NAMES_AS_KEYS
		or via json string '{"path": "/a/b/c", "version": "3", "use-secret-names-as-keys":  "true"}',
	*/
	var secretsConfigList []SecretConfig

	for _, secretConfigJSONString := range secretConfigs {
		secretConfig := SecretConfig{}
		var secretConfigData SecretConfigJSON

		err := json.Unmarshal([]byte(secretConfigJSONString), &secretConfigData)
		if err != nil {
			return nil, fmt.Errorf("unable to decode JSON from string %s - %+v", secretConfigJSONString, err)
		}

		secretConfig.Path = secretConfigData.Path
		secretConfig.Version = secretConfigData.Version
		secretConfig.UseSecretNamesAsKeys, _ = strconv.ParseBool(secretConfigData.UseSecretNamesAsKeys)
		GetKVConfig(client, &secretConfig)

		secretsConfigList = append(secretsConfigList, secretConfig)
	}

	vaultCfg.SecretsConfigList = secretsConfigList

	return vaultCfg, nil
}

func readSecret(client *api.Client, secretPath string) (*api.Secret, error) {
	log.Debugf("Getting Vault secrets from path: %s", secretPath)
	secret, secretError := client.Logical().Read(secretPath)
	if secretError != nil {
		return nil, fmt.Errorf("failed to read secret '%s' %v", secretPath, secretError)
	}

	if secret == nil {
		return nil, fmt.Errorf("Could not find a secret")
	}
	if secret.Data == nil {
		return nil, fmt.Errorf("Vault secret path not found %s", secretPath)
	}
	return secret, nil
}

func listKeys(client *api.Client, cfg SecretConfig) ([]string, error) {
	path := cfg.Path
	var err error
	log.Debugf("secret path ends with a \"/\" or has \"*\", listing keys from path: %s", path)

	if cfg.IsKVv2 {
		path = sanitizePath(path)
		path = AddPrefixToVKVPath(path, cfg.MountPath, "metadata")
	}

	data, err := client.Logical().List(path)

	if err != nil {
		return nil, fmt.Errorf("Error listing %s: %s", path, err)
	}

	if data == nil {
		return nil, fmt.Errorf("no keys found for list operation at: %s, check the path", path)
	}

	for _, w := range data.Warnings {
		log.Warnf("%+v", w)
	}
	keys := cast.ToStringSlice(data.Data["keys"])
	return keys, nil
}

func setSecretPath(cfg *SecretConfig, secretPath string) string {
	secretPath = sanitizePath(secretPath)
	var path string
	if cfg.IsKVv2 {
		path = AddPrefixToVKVPath(secretPath, cfg.MountPath, "data")
	} else {
		path = secretPath
	}
	return path
}

func filterByWildcard(keys []string, wildcard string) []string {
	log.Debugf("keys: %v", keys)
	var wildcardRegexp string
	// db*
	if strings.HasSuffix(wildcard, "*") {
		wildcardRegexp = fmt.Sprintf("^%s.+", strings.TrimSuffix(wildcard, "*"))
	}

	// *db
	if strings.HasPrefix(wildcard, "*") {
		wildcardRegexp = fmt.Sprintf(".+%s$", strings.TrimPrefix(wildcard, "*"))
	}

	// *db*
	if strings.HasPrefix(wildcard, "*") && strings.HasSuffix(wildcard, "*") {
		wildcard = strings.TrimPrefix(wildcard, "*")
		wildcard = strings.TrimSuffix(wildcard, "*")
		wildcardRegexp = fmt.Sprintf(".+%s(.+)?", wildcard)
	}

	log.Debugf("Using the wildcard pattern: %s", wildcardRegexp)
	pattern := regexp.MustCompile(wildcardRegexp)

	var filteredKeys []string

	for _, key := range keys {
		if pattern.MatchString(key) {
			filteredKeys = append(filteredKeys, key)
		}
	}

	if len(filteredKeys) == 0 {
		log.Warnf("keys did not match the path pattern %s, check your keys and path", wildcard)
	} else {
		log.Debugf("Filtered keys: %v", filteredKeys)
	}
	return filteredKeys
}

// RetrieveSecret retrieve secrets from vault
func RetrieveSecret(client *api.Client, cfg *SecretConfig) (map[string]interface{}, error) {
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
	var (
		keys         []string
		versionParam map[string][]string
		err          error
	)
	secretData := make(map[string]interface{})

	if strings.HasSuffix(cfg.Path, "/") || strings.Contains(cfg.Path, "*") || cfg.UseSecretNamesAsKeys {
		if cfg.UseSecretNamesAsKeys {
			cfg.Path = ensureTrailingSlash(cfg.Path)
		}

		var wildcard string
		if strings.Contains(cfg.Path, "*") {
			log.Warn("contains *")
			cfg.Path, wildcard = path.Split(cfg.Path)
			log.Warnf("path: %s, wildcard: %s", cfg.Path, wildcard)
		}
		keys, err = listKeys(client, *cfg)
		if err != nil {
			return nil, err
		}

		if wildcard != "" {
			keys = filterByWildcard(keys, wildcard)
		}

		log.Debugf("keys: %+v\n", keys)
		if len(keys) == 0 {
			return nil, fmt.Errorf("could not list keys under path: %s", cfg.Path)
		}
		if cfg.UseSecretNamesAsKeys {
			log.Debugf("Using secret names as keys")
		} else {
			log.Debugf("Using secret keys and values")
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

			// if secret version is passed
			if cfg.IsKVv2 && cfg.Version != "" {
				versionParam = map[string][]string{
					"version": {cfg.Version},
				}
				secret, err := client.Logical().ReadWithData(path, versionParam)
				if err != nil {
					return nil, err
				}
				return secret.Data, nil
			}

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
	// if secret version is passed
	if cfg.IsKVv2 && cfg.Version != "" {
		versionParam = map[string][]string{
			"version": {cfg.Version},
		}
		secret, err := client.Logical().ReadWithData(path, versionParam)
		if err != nil {
			return nil, err
		}
		if secret != nil {
			return secret.Data, nil
		}
		return nil, errors.New("could not read secret data")
	}

	secret, err := readSecret(client, path)

	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

// RetrieveSecrets iterate over secretConfigsList and retrieve each secret
func RetrieveSecrets(client *api.Client, vaultCfg *Config) (map[string]interface{}, error) {
	secretData := make(map[string]interface{})
	var err error

	for _, secretConfig := range vaultCfg.SecretsConfigList {
		secretConfigData := make(map[string]interface{})
		secretConfigData, err = RetrieveSecret(client, &secretConfig)
		if err != nil {
			return nil, fmt.Errorf("Error getting secrets from vault: %v", err)
		}

		data := CastSecretDataToStringMap(secretConfigData)
		for k, v := range data {
			secretData[k] = v
		}
	}

	return secretData, nil
}
