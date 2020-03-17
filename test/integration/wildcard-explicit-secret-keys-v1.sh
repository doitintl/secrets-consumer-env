#!/bin/bash
export DATABASE_URL=secret:DATABASE_URL
export DB_PASSWORD=secret:DB_PASSWORD
export VAULT_ROLE=milton
export VAULT_CAPATH=/Users/ami/doit/medium/vault-gke/vault-ca/ca.pem
export VAULT_PATH=secret_v1/service/
export VAULT_USE_SECRET_NAMES_AS_KEYS=true
export SECRET_PATH=${VAULT_PATH}
export VAULT_ROLE=milton
export TOKEN_PATH=/Users/ami/Desktop/token
exec go run ../../main.go ../../cmd-example.sh
