package test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/innovia/secrets-consumer-env/injector"
)

func injectSecrets(t *testing.T, secretData map[string]interface{}, environ []string, sanitized injector.SanitizedEnviron) ([]string, error) {
	sanitized, err := injector.InjectSecrets(secretData, environ, sanitized)
	if err != nil {
		return nil, err
	}
	return sanitized, nil
}

func TestSecretInjector(t *testing.T) {
	testCases := []struct {
		name       string
		environ    []string
		secretData map[string]interface{}
		sanitized  injector.SanitizedEnviron
		function   func(*testing.T, map[string]interface{}, []string, injector.SanitizedEnviron) ([]string, error)
		wants      []string
	}{
		{
			name: "Inject env vars with prefix only",
			environ: []string{
				"PATH=/usr/bin/some-path",
				"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.jNPniXcXag/Listeners",
				"COLORFGBG=15;0",
				"XPC_FLAGS=0x0",
				"VAULT_PATH=/secret/path",
				"VAULT_ROLE=milton",
				"API_KEY=secret:API_KEY",
				"DB_PASSWORD=vault:DB_PASSWORD",
			},
			secretData: map[string]interface{}{
				"API_KEY":     "qwe1234",
				"DB_PASSWORD": "s3cr3t",
			},
			sanitized: make(injector.SanitizedEnviron, 0, 8),
			function:  injectSecrets,
			wants: []string{
				"PATH=/usr/bin/some-path",
				"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.jNPniXcXag/Listeners",
				"COLORFGBG=15;0",
				"XPC_FLAGS=0x0",
				"API_KEY=qwe1234",
				"DB_PASSWORD=s3cr3t",
			},
		}, {
			name: "Inject env vars without prefix - get all secrets",
			environ: []string{
				"PATH=/usr/bin/some-path",
				"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.jNPniXcXag/Listeners",
				"COLORFGBG=15;0",
				"XPC_FLAGS=0x0",
				"VAULT_PATH=/secret/path",
				"VAULT_ROLE=milton",
			},
			secretData: map[string]interface{}{
				"API_KEY":     "qwe1234",
				"DB_PASSWORD": "s3cr3t",
			},
			sanitized: make(injector.SanitizedEnviron, 0, 8),
			function:  injectSecrets,
			wants: []string{
				"PATH=/usr/bin/some-path",
				"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.jNPniXcXag/Listeners",
				"COLORFGBG=15;0",
				"XPC_FLAGS=0x0",
				"API_KEY=qwe1234",
				"DB_PASSWORD=s3cr3t",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sanitized, err := testCase.function(t, testCase.secretData, testCase.environ, testCase.sanitized)
			if err != nil {
				t.Fatalf("error runing test %s, %v", testCase.name, err)
			}

			if !cmp.Equal(sanitized, testCase.wants) {
				t.Errorf("secretData = diff %v", cmp.Diff(sanitized, testCase.wants))
			}
		})
	}
}
