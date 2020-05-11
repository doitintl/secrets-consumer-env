package vault

import (
	"fmt"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

// GetServiceAccountToken read Kubernetes service account token
func GetServiceAccountToken(tokenPath string) ([]byte, error) {
	log.Info("Getting Kubernetes service account token from file...")
	jwt, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		err = fmt.Errorf(
			`failed to read service acccount token file %v,
			if you are trying to use another location use the TOKEN_PATH environment variable`,
			err,
		)
		return nil, err
	}
	return jwt, nil
}

// KubernetesBackendLogin Authenticate to Vault via Kubernetes Backend
func KubernetesBackendLogin(client *Client, vaultCfg *Config, jwt []byte) (string, error) {
	params := map[string]interface{}{"jwt": string(jwt), "role": vaultCfg.Role}
	log.Infof("Logging into Vault Kubernetes backend %s using the role %s", vaultCfg.KubernetesBackend, vaultCfg.Role)
	secretData, err := client.Logical.Write(vaultCfg.KubernetesBackend, params)
	if err != nil {
		return "", fmt.Errorf("failed login to Vault using Kubernetes backend %v", err)
	}
	clientToken := &secretData.Auth.ClientToken
	return *clientToken, nil
}
