// This script expect basic vault env vars to exist before execution
// a new set of env vars (sanitizedEnviron) is then made to hole only the env appears in the secret

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	vaultapi "github.com/hashicorp/vault/api"
	awsSecretManager "github.com/innovia/secrets-consumer-env/aws"
	gcpSecretManager "github.com/innovia/secrets-consumer-env/gcp"
	vaultSecretManager "github.com/innovia/secrets-consumer-env/vault"
)

type sanitizedEnviron []string

// Vault known Env Vars
var sanitizeEnvmap = map[string]bool{
	"VAULT_TOKEN":           true,
	"VAULT_ADDR":            true,
	"VAULT_CACERT":          true,
	"VAULT_CAPATH":          true,
	"VAULT_CLIENT_CERT":     true,
	"VAULT_CLIENT_KEY":      true,
	"VAULT_CLIENT_TIMEOUT":  true,
	"VAULT_CLUSTER_ADDR":    true,
	"VAULT_MAX_RETRIES":     true,
	"VAULT_REDIRECT_ADDR":   true,
	"VAULT_SKIP_VERIFY":     true,
	"VAULT_TLS_SERVER_NAME": true,
	"VAULT_CLI_NO_COLOR":    true,
	"VAULT_RATE_LIMIT":      true,
	"VAULT_NAMESPACE":       true,
	"VAULT_MFA":             true,
	"VAULT_ROLE":            true,
	"VAULT_PATH":            true,
}

// Appends variable an entry (name=value) into the environ list.
// VAULT_* variables are not populated into this list.
func (environ *sanitizedEnviron) append(iname interface{}, ivalue interface{}) {
	name, value := iname.(string), ivalue.(string)
	if _, ok := sanitizeEnvmap[name]; !ok {
		*environ = append(*environ, fmt.Sprintf("%s=%s", name, value))
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	})

	var vaultCfg *vaultSecretManager.Config
	var secretData map[string]interface{}
	var err error

	switch os.Getenv("SecretManager") {
	case "aws":
		secretData, err = awsSecretManager.RetrieveSecret()
	case "gcp":
		client, err := gcpSecretManager.NewSecretManagerClient()
		if err != nil {
			break
		}
		secretData, err = gcpSecretManager.RetrieveSecret(client)
	default:
		var gcpCfg *vaultSecretManager.GCPBackendConfig
		var err error

		vaultCfg, err = vaultSecretManager.ConfigureVaultAccess()
		if err != nil {
			log.Fatalf("Error configuring vault paramters: %v", err)
		}

		if vaultCfg.Backend == "gcp" {
			gcpCfg, err = vaultSecretManager.ConfigureGCPAccess()
		}

		client, err := vaultSecretManager.NewClientWithConfig(vaultapi.DefaultConfig(), vaultCfg, gcpCfg)

		if err != nil {
			log.Fatalf("Error creating vault client: %v", err)
		}

		vaultSecretManager.GetKVConfig(client.Client, vaultCfg)
		secretData, err = vaultSecretManager.RetrieveSecret(client.Logical, vaultCfg)
		if err != nil {
			log.Fatalf("Error getting secrets from vault: %v", err)
		}
	}

	if err != nil {
		log.Fatalf("Error retrieving secret: %v", err)
	}

	log.Info("Processing secrets from Secret Manager as environment variables")
	// get all env vars, this include the convention on secret:ENV_VAR to include it in the env vars
	environ := syscall.Environ()
	sanitized := make(sanitizedEnviron, 0, len(environ))

	// check each env var - if it has the secret: prefix append its value from vault to the env
	var data map[string]interface{}
	var key string

	for _, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		if strings.HasPrefix(value, ">>vault:") {
			value = strings.TrimPrefix(value, ">>")
		}

		if !strings.HasPrefix(value, "vault:") || !strings.HasPrefix(value, "secret:") {
			sanitized.append(name, value)
			continue
		}

		if strings.HasPrefix(value, "vault:") {
			key = strings.TrimPrefix(value, "vault:")
		}

		if strings.HasPrefix(value, "secret:") {
			key = strings.TrimPrefix(value, "secret:")
		}

		if strings.HasPrefix(value, "secret:") {
			data = vaultSecretManager.CastSecretDataToStringMap(secretData)

			if value, ok := data[key]; ok {
				sanitized.append(name, value)
			} else {
				fmt.Fprintf(os.Stderr, "Env var key: %s not found in secrets keys\n", key)
				os.Exit(1)
			}
		}
	}

	data = vaultSecretManager.CastSecretDataToStringMap(secretData)

	for name, value := range data {
		sanitized.append(strings.ToUpper(name), value)
	}

	log.Info("Launching command")
	var entrypointCmd []string
	if len(os.Args) == 1 {
		log.Fatalln(
			"no command is given, secrets-consumer-env can't determine the entrypoint (command),",
			" please specify it explicitly or let the kubernetes webhook query it (see documentation)",
		)
	} else {
		entrypointCmd = os.Args[1:]
	}

	// LookPath searches for an executable named file in the directories named by the PATH
	// environment variable. If file contains a slash, it is tried directly and the
	// PATH is not consulted.
	//  The result may be an absolute path or a path relative to the current directory.
	binary, err := exec.LookPath(os.Args[1])
	if err != nil {
		log.Fatalln("binary not found", entrypointCmd[0])
	}

	log.Infof("Running command using execv: %s %s", binary, entrypointCmd)
	err = syscall.Exec(binary, entrypointCmd, sanitized)
	if err != nil {
		log.Fatalln("failed to exec process", binary, entrypointCmd, err.Error())
	}
}
