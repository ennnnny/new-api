package openai

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"one-api/common"
	"strings"
	"time"
)

type GerProfile struct {
	User struct {
		Orgs struct {
			Object string `json:"object"`
			Data   []struct {
				Object             string `json:"object"`
				Id                 string `json:"id"`
				Created            int64  `json:"created"`
				Name               string `json:"name"`
				Description        string `json:"description"`
				Personal           bool   `json:"personal"`
				Priority           int    `json:"priority"`
				VerificationStatus string `json:"verification_status"`
				Settings           struct {
				} `json:"settings"`
				Role string `json:"role"`
			} `json:"data"`
		} `json:"orgs"`
	} `json:"user"`
}

type GerAuthenticateResponse struct {
	Data struct {
		RequestId    string `json:"request_id"`
		SessionJwt   string `json:"session_jwt"`
		SessionToken string `json:"session_token"`
		StatusCode   int    `json:"status_code"`
	} `json:"data"`
}

func getMd5String(str string) string {
	hash := md5.New()
	hash.Write([]byte(str))
	hashInBytes := hash.Sum(nil)
	keyMd5 := hex.EncodeToString(hashInBytes)

	return keyMd5
}

func initGerAccount(key string) map[string]string {
	var organization, token string

	if strings.Contains(key, "#") {
		splitStr := strings.Split(key, "#")
		if len(splitStr) == 2 {
			organization = splitStr[0]
			key = splitStr[1]
		}
	}
	keyMd5 := getMd5String(key)
	if common.RedisEnabled {
		var err error
		if organization == "" {
			organization, err = common.RedisGet(fmt.Sprintf("groqAccountOrg:%s", keyMd5))
			if err != nil {
				organization = ""
			}
		}
		token, err = common.RedisGet(fmt.Sprintf("groqAccountToken:%s", keyMd5))
		if err != nil {
			token = ""
		}
	}
	if organization == "" || token == "" {
		if strings.HasPrefix(key, "eyJhbGciOiJSUzI1NiI") {
			if organization == "" {
				organization = GerOrganizationId(key)
			}
			token = key
		}
		if len(key) == 44 {
			tokenTemp, err := GerGetSessionToken(key)
			if err == nil {
				token = tokenTemp.Data.SessionJwt
				if organization == "" {
					organization = GerOrganizationId(token)
				}
			}
		}
		if common.RedisEnabled {
			if organization != "" {
				err := common.RedisSet(fmt.Sprintf("groqAccountOrg:%s", keyMd5), organization, 60*time.Minute)
				if err != nil {
					common.SysError("Redis set organization error: " + err.Error())
				}
			}
			if token != "" {
				err := common.RedisSet(fmt.Sprintf("groqAccountToken:%s", keyMd5), token, 3*time.Minute)
				if err != nil {
					common.SysError("Redis set token error: " + err.Error())
				}
			}
		}
	}

	common.SysLog("initGerAccount：" + organization + "/#/" + token)
	data := map[string]string{
		"organization": organization,
		"token":        token,
	}
	return data
}

func GerBaseHeader(c *http.Request) {
	c.Header.Set("accept", "*/*")
	c.Header.Set("accept-language", "zh-CN,zh;q=0.9")
	c.Header.Set("content-type", "application/json")
	c.Header.Set("origin", "https://groq.com")
	c.Header.Set("referer", "https://groq.com/")
	c.Header.Set("sec-ch-ua", `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`)
	c.Header.Set("sec-ch-ua-mobile", "?0")
	c.Header.Set("sec-ch-ua-platform", `"Windows"`)
	c.Header.Set("sec-fetch-dest", "empty")
	c.Header.Set("sec-fetch-mode", "cors")
	c.Header.Set("sec-fetch-site", "cross-site")
	c.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
}

func GerOrganizationId(apiKey string) string {
	client := http.Client{}

	req, err := http.NewRequest("GET", "https://api.groq.com/platform/v1/user/profile", nil)
	if err != nil {
		return ""
	}
	GerBaseHeader(req)
	req.Header.Set("Authorization", "Bearer "+apiKey)

	//log
	headerStr := ""
	for cKey, values := range req.Header {
		for _, value := range values {
			headerStr += cKey + ": " + value + ";"
		}
	}
	common.SysLog("GerOrganizationIdHeaders：" + headerStr)

	res, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()

	newBodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		common.SysLog("GerOrganizationIdBody：" + err.Error())
	}
	common.SysLog("GerOrganizationIdBody：" + string(newBodyByte))

	var result GerProfile
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return ""
	}
	return result.User.Orgs.Data[0].Id
}

func GerGetSessionToken(apiKey string) (GerAuthenticateResponse, error) {
	if apiKey == "" {
		return GerAuthenticateResponse{}, errors.New("session token is empty")
	}
	authorization := GerGenerateRefreshToken(apiKey)

	client := http.Client{}
	req, err := http.NewRequest("POST", "https://web.stytch.com/sdk/v1/sessions/authenticate", strings.NewReader(`{}`))
	if err != nil {
		return GerAuthenticateResponse{}, errors.New("create request failed")
	}
	GerBaseHeader(req)
	req.Header.Set("Authorization", "Basic "+authorization)
	req.Header.Set("x-sdk-client", "eyJldmVudF9pZCI6ImV2ZW50LWlkLWQ4M2IwNTI4LTllNjMtNDkxYi05OGM5LWUyZmJmODY4MWRlZiIsImFwcF9zZXNzaW9uX2lkIjoiYXBwLXNlc3Npb24taWQtNjRlNGI4ZTItOWM2NS00MDFlLWIyMjUtYjk4MWYxNGRjMTRjIiwicGVyc2lzdGVudF9pZCI6InBlcnNpc3RlbnQtaWQtOTNlZWYwNWUtYWE0OS00OWJhLThhNjktYWVjZTA3ZTZiM2NmIiwiY2xpZW50X3NlbnRfYXQiOiIyMDI0LTA0LTI2VDExOjM4OjU1Ljk0NVoiLCJ0aW1lem9uZSI6IkFzaWEvU2hhbmdoYWkiLCJzdHl0Y2hfdXNlcl9pZCI6InVzZXItbGl2ZS1kZDM4ODRiYS01M2YyLTRjNjEtYTI5Yi02NzEwNmExMDMxNTciLCJzdHl0Y2hfc2Vzc2lvbl9pZCI6InNlc3Npb24tbGl2ZS01ZjQ5NDViZS1kNTIyLTQyZWEtYTEzNC01MWE4YzM2OTBkN2UiLCJhcHAiOnsiaWRlbnRpZmllciI6ImNvbnNvbGUuZ3JvcS5jb20ifSwic2RrIjp7ImlkZW50aWZpZXIiOiJTdHl0Y2guanMgSmF2YXNjcmlwdCBTREsiLCJ2ZXJzaW9uIjoiNC42LjAifX0=")
	req.Header.Set("x-sdk-parent-host", "https://groq.com")

	res, err := client.Do(req)
	if err != nil {
		return GerAuthenticateResponse{}, errors.New("request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return GerAuthenticateResponse{}, errors.New("authenticate failed")
	}
	var result GerAuthenticateResponse
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return GerAuthenticateResponse{}, err
	}
	return result, nil
}

func GerGenerateRefreshToken(apiKey string) string {
	prefix := "public-token-live-26a89f59-09f8-48be-91ff-ce70e6000cb5:" + apiKey
	return base64.StdEncoding.EncodeToString([]byte(prefix))
}