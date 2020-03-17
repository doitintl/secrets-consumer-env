#!/bin/bash

export VAULT_PATH=secret_v2/milton
export VAULT_USE_SECRET_NAMES_AS_KEYS=false
export VAULT_ROLE=milton
export VAULT_SECRET_VERSION="2"
export TOKEN_PATH=/Users/ami/Desktop/token
export SECRET_PATH=${VAULT_PATH}
exec go run ../../main.go ../../cmd-example.sh
