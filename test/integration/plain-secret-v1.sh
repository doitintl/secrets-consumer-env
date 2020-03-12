#!/bin/bash

export API_KEY=secret:API_KEY
export VAULT_PATH=secret_v1/service/API
export VAULT_ROLE=milton
export TOKEN_PATH=/Users/ami/Desktop/token
export VAULT_USE_SECRET_NAMES_AS_KEYS=false
export SECRET_PATH=${VAULT_PATH}
exec go run ../../main.go ../../cmd-example.sh
