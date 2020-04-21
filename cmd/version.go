package cmd

import (
	"fmt"

	"github.com/doitintl/secrets-consumer-env/pkg/version"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Secrets Consumer Env",
	Long:  `Print the version of Secrets Consumer Env.`,
	Run: func(cmd *cobra.Command, args []string) {
		secretsConsumerEnvVersion := version.GetVersion()
		gitCommitID := version.GetGitCommitID()
		fmt.Printf("secret consumer env version: %v\n", secretsConsumerEnvVersion)
		fmt.Printf("commit: %v\n", gitCommitID)
	},
}
