# Secrets Consumer Env

There are a few secret managers that holds secrets, the problem becomes how to consume these secrets
securely.

The Secrets Consumer Env creates a new shell environment, and fetch the secrets from the secret engine
adding them to the environment variables on the new shell and then calling the syscall.execv which will
replace the running process with the given process, that given process will inherit all environment variables.

In the world of containers, its important that the process running in it should get the PID 1 so
that a sig TERM will work properly.

Because `secrets-consumer-env` calls `execv` with given command - only the given command (inherits)
will have access to the env vars the operating system / docker container will not have any of the
secrets exposed.

This tool can run standalone outside of kubernetes or using the Kubernetes mutation webhook.

This tool works with the following secrets managers:

* GCP Secret Manager
* AWS Secret Manager
* Hashicorp Vault
  * Kubernetes backend login (Default)
  * GCP backend login

## QuickStart

1. Set the tool to work with the preferred secret manager:

  `export SecretManager=aws`

  `export SecretManager=gcp`

  vault is the default secret manager
2. Set the environment variables per secret manager of your choice
3. You can run the following command to test `secrets-consumer-env`
   **Important:** do not use double qoutes as it will be first evaluated by your shell and not by the sub-command

   ```bash
   secrets-consumer-env /bin/bash -c 'echo API $API_KEY'
   ```

## AWS Secret Manager

AWS secret manager can hold secrets in a json format. the secret can be rotated using a lambda function
and the only versions that AWS secret manager knows are `CURRENT_VERSION` and `PREVIOUS_VERSION`
you have the option of specifying `PREVIOUS_VERSION=true` to fetch previous version

| Name| Description | Required | Default|
| :--- |:---|:---:|:---|
| REGION            | AWS Region for secret manager | No | us-east-1          |
| SECRET_NAME       | secret manager secret name    | Yes| - |
| PREVIOUS_VERSION  | If using lambda to rotate secrets you can get the previous version | No | If not supplied - the current version will be used |
| ROLE_ARN          | Role arn with access to the secret, this requires also permissions on the KMS key for that role | No | -

## GCP Secret Manager

GCP secrets manager can hold secrets in plain text, it does not bind a format, in order to work with this tool
you must use a JSON format for your secrets.

GCP secrets manager can hold a numerical version number, and you can specify it using `SECRET_VERSION`

This app is working using the [Application Default Credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/login)

you must either use `export GOOGLE_APPLICATION_CREDENTIALS=<path-to-service-account-json-file>` or use the command

```bash
gcloud auth application-default login
```

| Name| Description | Required | Default|
| :--- |:---|:---:|:---|
| PROJECT_ID | GCP  Project ID the Secret Manager is on | Yes | - |
| SECRET_NAME     | secret manager secret name    | Yes| - |
| SECRET_VERSION  | secret version number | No | "latest" |
| GOOGLE_APPLICATION_CREDENTIALS | path to GCP service account json file with permission to the secret | No | - |

## Hashicorp VAULT Secret Manager

Vault can store secrets in either v1 (no versions) or v2 (versioned secret)

The API calls are different paths and this tool automatically adjust the secret path based on the secret backend version (v1 or v2)

Ways to use Vault secrets:

1. you can use Vault with a secret path that contains a JSON
2. you can use Vault paths as if they were a file system, one use case would be to have a path with secrets as subpaths, each secret name
would be used as the key name and will contain a single value.
the advantage of this approach is that you don't have to read, and append a value when you want to add or edit a value in it

```console
/secret/some/path/
-- API_KEY
    -- value: secret-api-key
-- DB_PASSWORD
    -- value: 1234
```

this tool will read all the sub paths from `/secret/some/path/` and you will need to use the `VAULT_USE_SECRET_NAMES_AS_KEYS=true` env var to make it work.
3. you can use vault paths as in the previous option, but if you use the env var `VAULT_USE_SECRET_NAMES_AS_KEYS=true` it will get all the secrets **key=values** from all the paths below the path `/secret/some/path/`
4. you can choose which env var to export by using the following convention: `ENV_NAME_TO_BE_EXPORTED="secret:<SECRET_KEY>"`

Vault secret path can be either treated as a directory by using a trailing slash "/"
or it can be use as a wildcard for example: `db*, *db, *user*`

### Using Kubernetes backend

| Name| Description | Required | Default|
| :--- |:---|:---:|:---|
| VAULT_CAPATH | Vault CA public certificate path | Yes if using TLS | - |
| VAULT_PATH  | vault secrets path, can be a secret path ending with a "/" to get all secrets below that path | Yes | - |
| VAULT_ROLE  | vault role to access the secret | Yes | - |
| TOKEN_PATH | kubernetes service account JWT token path | No | "/var/run/secrets/kubernetes.io/serviceaccount/token" |
| VAULT_BACKEND | kubernetes or gcp vault backend | No | "kubernetes" |
| VAULT_SECRET_VERSION | vault secret version  | No | latest version |
| VAULT_USE_SECRET_NAMES_AS_KEYS | allow retrieving secrets from subpath while using the secret name as the key (single value secret only) | No | false|

### Using GCP / GCE backend

| Name| Description | Required | Default|
| :--- |:---|:---:|:---|
| VAULT_CAPATH | Vault CA public certificate path | Yes if using TLS | - |
| VAULT_PATH  | vault secrets path, can be a secret path ending with a "/" to get all secrets below that path | Yes | - |
| VAULT_ROLE  | vault role to access the secret | Yes | - |
| PROJECT_ID | GCP project ID | Yes | - |
| GOOGLE_APPLICATION_CREDENTIALS | path to GCP service account json file with permission to the secret | No | - |
 | Service account JSON file key | Yes | - |
| VAULT_BACKEND | kubernetes or gcp vault backend | should be explicitly set to "gcp" | Yes | - |
| VAULT_SECRET_VERSION | vault secret version  | No | latest version |
| VAULT_USE_SECRET_NAMES_AS_KEYS | allow retrieving secrets from subpath while using the secret name as the key (single value secret only) | No | false|
