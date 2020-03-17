#!/bin/bash

export VAULT_ROLE=milton
export VAULT_CAPATH=/Users/ami/doit/medium/vault-gke/vault-ca/ca.pem
export VAULT_PATH=secret_v2/secret/secret_v2/service/
export VAULT_USE_SECRET_NAMES_AS_KEYS=false
export SECRET_PATH=${VAULT_PATH}
export VAULT_ROLE=milton
export TOKEN_PATH=/Users/ami/Desktop/token
exec go run ../../main.go ../../cmd-example.sh
