#! /bin/bash

if [ "${VAULT_USE_SECRET_NAMES_AS_KEYS}" = "true" ]; then
    echo "testing subtree each path as key name with a single value"
    echo "API_KEY: $API_KEY"
    echo "DATABASE_URL: $DATABASE_URL"
    echo "DB_PASSWORD: $DB_PASSWORD"
    exit 0
fi

case $SECRET_PATH in
    */)
    echo "testing subtree with multiple secret values"
    env | grep -i ami_
    exit 0
    ;;
    *)
    echo "testing plain secret with explcit key"
    echo "API_KEY: $API_KEY"
    exit 0
    ;;
esac




