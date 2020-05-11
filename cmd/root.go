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
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/doitintl/secrets-consumer-env/pkg/injector"
	"github.com/doitintl/secrets-consumer-env/pkg/version"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

//The verbose flag value
var v string
var command string

// var args []string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "secrets-consumer-env",
	Short: "Consume secrets from AWS, GCP or Hashicorp Vault",
	Long: `There are a few secret managers that holds secrets, the problem becomes how to consume these secrets
securely.

The Secrets Consumer Env creates a new shell environment, and fetch the secrets from the secret engine
adding them to the environment variables on the new shell and then calling the` + " `syscall.execv` " + `which will
replace the running process with the given process, that given process will inherit all environment variables.

In the world of containers, its important that the process running in it should get the PID 1 so
that a sig TERM will work properly.

will have access to the env vars, the operating system / docker container will not have any of the
secrets exposed.

This tool can either run as a standalone outside of kubernetes or using the Kubernetes mutation webhook.

This tool works with the following secrets managers:

* GCP Secret Manager
* AWS Secret Manager
* Hashicorp Vault
  * Kubernetes backend login (Default)
  * GCP backend login

### CLI Commands

* ` + "`aws` " + ` - enable the AWS Secret Manager
* ` + "`gcp` " + ` - enable the GCP Secret Manager
* ` + "`vault` " + ` - enable the Vault Secret Manager

**Note: The double dash symbol “–-” is used to separate the arguments you want to pass to the command from the secrets-consumer-env arguments.**

**Important: Do not use double-quotes for your command as it will first be evaluated by your shell and not by the secrets-consumer-env.**`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	fmt.Printf("Secrets Consumer Env Version: %s Commit: %s\n\n", version.GetVersion(), version.GetGitCommitID())
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.secrets-consumer-env.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	// RootCmd.PersistentFlags().StringVarP(&command, "command", "c", "", "Command to be execute post secret injection")
	// RootCmd.PersistentFlags().StringArrayVarP(&args, "args", "a", []string{}, "Command arguments that will be appended to the command")
	RootCmd.PersistentFlags().StringVarP(&v, "verbosity", "v", logrus.InfoLevel.String(), "Log level (debug, info, warn, error, fatal, panic")

	RootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := setUpLogs(os.Stdout, v); err != nil {
			return err
		}
		return nil
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			exitWithError("error getting home directory", err)
		}

		// Search config in home directory with name ".secrets-consumer-env" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".secrets-consumer-env")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

//setUpLogs set the log output ans the log level
func setUpLogs(out io.Writer, level string) error {
	logrus.SetOutput(out)
	logrus.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	return nil
}

func processSecrets(secretData map[string]interface{}, args []string) {
	log.Info("Processing secrets from Secret Manager as environment variables")
	var err error
	environ := os.Environ()
	sanitized := make(injector.SanitizedEnviron, 0, len(environ))
	sanitized, err = injector.InjectSecrets(secretData, environ, sanitized)
	if err != nil {
		exitWithError("error injecting secrets", err)
	}

	if len(args) == 0 {
		const msg = `
		no command is given, secrets-consumer-env can't determine the entrypoint (command)
			please specify it explicitly or let the kubernetes webhook query it (see documentation)
		`
		exitWithError(msg, nil)
	}
	// LookPath searches for an executable named file in the directories named by the PATH
	// environment variable. If file contains a slash, it is tried directly and the
	// PATH is not consulted.
	//  The result may be an absolute path or a path relative to the current directory.
	binary, err := exec.LookPath(args[0])
	if err != nil {
		exitWithError(fmt.Sprintf("binary not found %s", args[0]), nil)
	}

	log.Infof("Running command using execv: %s", strings.Join(args, " "))
	err = syscall.Exec(binary, args, sanitized)
	if err != nil {
		exitWithError(fmt.Sprintf("failed to exec process %v with args: %v", binary, args), err)
	}
}

func exitWithError(msg string, err error) {
	log.Fatalf("%s: %v", msg, err)
}
