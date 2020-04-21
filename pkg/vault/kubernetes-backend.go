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
func KubernetesBackendLogin(client *Client, role string, jwt []byte) (string, error) {
	params := map[string]interface{}{"jwt": string(jwt), "role": role}
	log.Infof("Logging into Vault Kubernetes backend using the role %s", role)
	secretData, err := client.Logical.Write("auth/kubernetes/login", params)
	if err != nil {
		return "", fmt.Errorf("failed login to Vault using Kubernetes backend %v", err)
	}
	clientToken := &secretData.Auth.ClientToken
	return *clientToken, nil
}
