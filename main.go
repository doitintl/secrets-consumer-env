// This script expect basic vault env vars to exist before execution
// a new set of env vars (SanitizedEnviron) is then made to hole only the env appears in the secret

package main

import (
	"os"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"

	vaultapi "github.com/hashicorp/vault/api"
	awsSecretManager "github.com/innovia/secrets-consumer-env/aws"
	gcpSecretManager "github.com/innovia/secrets-consumer-env/gcp"
	injector "github.com/innovia/secrets-consumer-env/injector"
	vaultSecretManager "github.com/innovia/secrets-consumer-env/vault"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	})

	var vaultCfg *vaultSecretManager.Config
	var secretData map[string]interface{}
	var err error
	secretManager := os.Getenv("SecretManager")

	switch secretManager {
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
	sanitized := make(injector.SanitizedEnviron, 0, len(environ))
	sanitized, err = injector.InjectSecrets(secretData, environ, sanitized)
	if err != nil {
		log.Fatalf("error injecting secrets: ")
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
