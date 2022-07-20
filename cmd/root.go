package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	url    string
	vulnId int
)
var rootCmd = &cobra.Command{
	Use:   "Seeyoner",
	Short: "Seeyoner",
	Long:  `一个简单的致远OA安全测试工具，目的是为了协助漏洞自查、修复工作。`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
