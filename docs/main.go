package main

import (
	"fmt"

	"github.com/doitintl/secrets-consumer-env/cmd"
	"github.com/spf13/cobra/doc"
)

func main() {
	err := doc.GenMarkdownTree(cmd.RootCmd, ".")
	if err != nil {
		fmt.Println(err)
	}
}
