package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	VulnNames = []string{
		//"log4j-RCE",
		"seeyon<8.0_fastjson反序列化",
		"thirdpartyController.do管理员session泄露",
		"webmail.do任意文件下载（CNVD-2020-62422）",
		"ajax.do未授权&任意文件上传",
		"getSessionList泄露Session",
		"htmlofficeservlet任意文件上传",
		"initDataAssess.jsp信息泄露",
		"DownExcelBeanServlet信息泄露",
		"createMysql.jsp数据库信息泄露",
		"test.jsp路径",
		"setextno.jsp路径",
		"status.jsp路径（状态监控页面）"}
)
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "列出所有漏洞信息",
	Long:  `完整的漏洞列表及对应ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		for i, v := range VulnNames {
			fmt.Printf("【%v】%v\n", i+1, v)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
