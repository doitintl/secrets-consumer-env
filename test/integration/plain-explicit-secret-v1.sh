#!/bin/bash

export API_KEY=secret:api_key
export VAULT_PATH=secrets/v1/some/secrets/path
export VAULT_ROLE=tester
export TOKEN_PATH=/Users/ami/Desktop/token
export VAULT_USE_SECRET_NAMES_AS_KEYS=false
export SECRET_PATH=${VAULT_PATH}
exec go run ../../main.go vault ../../cmd-example.sh
