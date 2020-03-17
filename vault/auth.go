package vault

import (
	vaultapi "github.com/hashicorp/vault/api"
)

// Config configuration for Vault
type Config struct {
	Role                 string
	Path                 string // If Path ends with a / or contains * it will treat it as a wildcard path
	TokenPath            string
	Backend              string
	UseSecretNamesAsKeys bool
	IsKVv2               bool
	MountPath            string
	Version              string // If passed, the value at the version number will be returned
}

// Client is a Vault client with Kubernetes support
type Client struct {
	Client  *vaultapi.Client
	Logical *vaultapi.Logical
}

// NewClientWithConfig create a new vault client
func NewClientWithConfig(config *vaultapi.Config, vaultCfg *Config, gcpCfg *GCPBackendConfig) (*Client, error) {
	var clientToken string
	var err error
	rawClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	logical := rawClient.Logical()
	client := &Client{Client: rawClient, Logical: logical}

	switch vaultCfg.Backend {
	case "gcp":
		clientToken, err = GCPBackendLogin(client, gcpCfg, vaultCfg)
		if err != nil {
			return nil, err
		}
	default:
		jwt, err := GetServiceAccountToken(vaultCfg.TokenPath)
		if err != nil {
			return nil, err
		}
		clientToken, err = KubernetesBackendLogin(client, vaultCfg.Role, jwt)
		if err != nil {
			return nil, err
		}
	}

	if err == nil {
		rawClient.SetToken(string(clientToken))
	} else {
		return nil, err
	}
	return client, nil
}
