/*
Copyright © 2020 DoiT International <ami.mahloof@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	awsSDK "github.com/aws/aws-sdk-go/aws"
	aws "github.com/doitintl/secrets-consumer-env/pkg/aws"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	region          string
	secretNameAWS   string
	previousVersion string
	roleARN         string
)

// awsCmd represents the aws command
var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Secrets Consumer for AWS Secret Manager",
	Long: `AWS secret manager can hold secrets in a json format. the secret can be rotated using a lambda function
and the only versions that AWS secret manager knows are CURRENT_VERSION and PREVIOUS_VERSION
you have the option of specifying PREVIOUS_VERSION=true to fetch previous version`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			secretData map[string]interface{}
			err        error
		)

		cfg := &aws.Config{
			Region:          region,
			RoleARN:         roleARN,
			PreviousVersion: previousVersion,
			SecretName:      awsSDK.String(secretNameAWS),
		}

		secretData, err = aws.RetrieveSecret(cfg)
		if err != nil {
			exitWithError("Error getting secrets from AWS Secret manager", err)
		}
		processSecrets(secretData, args)
	},
}

func init() {
	RootCmd.AddCommand(awsCmd)

	viper.SetDefault("region", "us-east-1")
	viper.SetDefault("role_arn", "")
	viper.SetDefault("secret_name", "")
	viper.SetDefault("previous_version", "")
	viper.AutomaticEnv()

	awsCmd.Flags().StringVar(&region, "region", viper.GetString("region"), "AWS Region for the Secret Manager (default: us-east-1)")
	awsCmd.Flags().StringVar(&roleARN, "role-arn", viper.GetString("role_arn"), "AWS Role ARN with access to the secret, this requires also permissions on the KMS key for that role")
	awsCmd.Flags().StringVar(&secretNameAWS, "secret-name", viper.GetString("secret_name"), "AWS Secret Name")
	awsCmd.Flags().StringVar(&previousVersion, "previous-version", viper.GetString("previous_version"), "If using lambda to rotate secrets you can get the previous version (default: current version)")
}
