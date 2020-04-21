/*
Copyright © 2020 DoiT International <ami.mahloof@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"errors"

	vault "github.com/doitintl/secrets-consumer-env/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// secretConfigs in JSON strings format
var (
	secretConfigs             []string
	vaultBackend              string
	tokenPath                 string
	vaultRole                 string
	vaultPath                 string
	secretVersion             string
	vaultUseSecretNamesAsKeys bool
	GCPBackendProjectID       string
	credsPath                 string
	secretManager             string
)

// vaultCmd represents the vault command
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Fetch and inject secrets from Vault to a given command",
	Long: `Fetch and inject secrets from Vault to a given command

Vault can store secrets in either KV v1 (no versions) or KV v2 (versioned secret),
the API calls are on different paths and secrets-consumer-env will automatically adjust the
secret path based on the secret backend version (v1 or v2)

secrets-consumer-env can login to kubernetes backend (default) or GCP backend.

Ways to use Vault secrets:
--------------------------

1. You can use Vault with a secret path that contains a JSON

2. You can use Vault paths as if they were a file system, one use case would be to have a path with secrets as sub-paths, each secret name would be used as the key name and will contain a single value.

For example:
------------
A list of secrets names (keys) secrets/kvV2/service/:

secrets/kvV2/service/API
|- value: qwerty1234

secrets/kvV2/service/DATABASE_URL
|- value: http://127.0.0.1:3306

secrets/kvV2/service/SOME_PASSWORD
|- value: s3cr3t123

In this case we need the secret name to be the key, and the value to be the actual value for that key

Or it can be a list of secrets with multiple key values secrets/kvV2/service:

secrets/kvV2/service/app
|- API_KEY: qwerty1234
|- DATABASE_URL http://127.0.0.1:3306

secrets/kvV2/service/database
|- USER_NAME: admin
|- PASSWORD: s3cr3t

The advantage of this approach is that you don't have to read, and append a value when you want to add or edit a value in it

3. You can also use multiple secrets if you pass the flag --secret-config with following convention:
   {"path": "some/secrets/path/", "use-secret-names-as-keys":  true, version: "5"} multiple times

4. you can use explicit secrets by using the following convention: ENV_NAME_TO_BE_EXPORTED="secret:<SECRET_KEY>",
   only these variables will be available to your given command/process.

5. Vault secret path can be either treated as a directory by using a trailing slash "/" or it can be use as a wildcard for example: db*, *db, *user*`,
	Args: validateConfig,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		secretData := make(map[string]interface{})
		vaultCfg := &vault.Config{
			Role:      vaultRole,
			TokenPath: tokenPath,
			Backend:   vaultBackend,
		}
		gcpCfg := &vault.GCPBackendConfig{
			Project:        GCPBackendProjectID,
			CredsPath:      credsPath,
			ServiceAccount: "",
		}

		if vaultPath != "" {
			var secretConfig vault.SecretConfig
			secretConfig.Version = secretVersion
			secretConfig.UseSecretNamesAsKeys = vaultUseSecretNamesAsKeys
			secretConfig.Path = vaultPath
			secretJSON, _ := json.Marshal(secretConfig)
			secretConfigs = append(secretConfigs, string(secretJSON))
		}

		client, err := vault.NewClientWithConfig(vaultapi.DefaultConfig(), vaultCfg, gcpCfg)
		if err != nil {
			exitWithError("Error creating Vault client", err)
		}

		vaultCfg, err = vault.ConfigureVaultSecrets(client.Client, secretConfigs, vaultCfg)
		if err != nil {
			exitWithError("Error configuring Vault paramters", err)
		}

		secretData, err = vault.RetrieveSecrets(client.Client, vaultCfg)
		if err != nil {
			exitWithError("Error retrieving secrets from Vault", err)
		}

		processSecrets(secretData, args)
	},
}

func validateConfig(cmd *cobra.Command, args []string) error {
	if vaultBackend == "gcp" {
		err := validateGCPConfig(GCPBackendProjectID, credsPath)
		if err != nil {
			return err
		}
	}

	if vaultRole == "" {
		return errors.New("Vault role is missing, pass it via --role flag or use VAULT_ROLE environment variable")
	}

	if vaultPath == "" && len(secretConfigs) == 0 {
		return errors.New("Vault secret path is missing  pass it via --path flag, or set VAULT_PATH environment variable,  you can also use --secret-config flag")
	}

	return nil
}

func init() {
	RootCmd.AddCommand(vaultCmd)

	viper.SetDefault("vault_backend", "kubernetes")
	viper.SetDefault("vault_role", "")
	viper.SetDefault("token_path", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	viper.SetDefault("vault_path", "")
	viper.SetDefault("secret_version", "")
	viper.SetDefault("names_as_keys", false)

	//GCP Backend login
	viper.SetDefault("project_id", "")
	viper.SetDefault("google_application_credentials", "")

	viper.AutomaticEnv()

	// Create flags to variables
	vaultCmd.Flags().StringVarP(&vaultBackend, "backend", "b", viper.GetString("vault_backend"), "Vault authentication backend [kubernetes, gcp]")
	vaultCmd.Flags().StringVar(&GCPBackendProjectID, "project-id", viper.GetString("project_id"), "GCP Project ID for GCP backend login")
	vaultCmd.Flags().StringVarP(&credsPath, "google-application-credentials", "a", viper.GetString("google_application_credentials"), "The file path to the GCP service account json file with permission to the secret")

	// Role, and Token Path location for kubernetes backend login
	vaultCmd.Flags().StringVar(&vaultRole, "role", viper.GetString("vault_role"), "Vault role (required)")
	vaultCmd.Flags().StringVar(&tokenPath, "token-path", viper.GetString("token_path"), "Kubernetes service account JWT token file path")

	// Single secret
	vaultCmd.Flags().StringVar(&vaultPath, "path", viper.GetString("vault_path"), "Vault secrets path, can be a secret path ending with a \"/\" to get all secrets below that path")
	vaultCmd.Flags().StringVar(&secretVersion, "version", viper.GetString("secret_version"), "Secret version if using a KVv2 (default \"latest\")")
	vaultCmd.Flags().BoolVar(&vaultUseSecretNamesAsKeys, "names-as-keys", viper.GetBool("names_as_keys"), "Use secret names as keys (default false)")

	// Multiple secrets via JSON string
	vaultCmd.Flags().StringArrayVarP(
		&secretConfigs,
		"secret-config",
		"",
		[]string{},
		"multiple secrets in JSON string like: '{\"path\": \"/some/secret/path\", \"version\": \"3\", \"use-secret-names-as-keys\":  true}' can be specified a multiple times",
	)
}
