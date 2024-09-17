package openai

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"one-api/common"
	"one-api/dto"
	"one-api/model"
	relaycommon "one-api/relay/common"
	"one-api/service"
	"strings"
	"sync"
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

type Cache struct {
	mu    sync.RWMutex
	items map[string]interface{}
}

func (c *Cache) HelpCacheGet(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if found {
		cacheTime := item.(map[string]interface{})["cacheTime"].(int64)
		if cacheTime < time.Now().Unix() {
			delete(c.items, key)
			return nil, false
		} else {
			value := item.(map[string]interface{})["value"]
			return value, true
		}
	}
	return nil, false
}

func HelpNewCache() *Cache {
	return &Cache{
		items: make(map[string]interface{}),
	}
}

var helpCache = HelpNewCache()

func (c *Cache) HelpCacheSet(key string, value interface{}, expiredTime int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = map[string]interface{}{
		"value":     value,
		"cacheTime": time.Now().Unix() + expiredTime,
	}
}

func InitNAccount(key string) map[string]string {
	userId, nextAction, token := "", "", ""

	mode := "token"
	splitStr := strings.Split(key, "#")
	if len(splitStr) == 3 {
		temp := splitStr[2]
		if strings.HasPrefix(temp, "base64") {
			userId = splitStr[0]
			nextAction = splitStr[1]
			token = splitStr[2]
		} else {
			mode = "account"
			nextAction = splitStr[0]
			account := splitStr[1]
			password := splitStr[2]
			if common.RedisEnabled {
				cacheUserId, err := common.RedisGet(fmt.Sprintf("notdiamondUserId:%s", nextAction))
				if err == nil {
					userId = cacheUserId
				}
				cacheToken, err := common.RedisGet(fmt.Sprintf("notdiamondToken:%s", nextAction))
				if err == nil {
					token = cacheToken
				}
			} else {
				cacheUserId, found := helpCache.HelpCacheGet(fmt.Sprintf("notdiamondUserId:%s", nextAction))
				if found {
					userId = cacheUserId.(string)
				}
				cacheToken, found := helpCache.HelpCacheGet(fmt.Sprintf("notdiamondToken:%s", nextAction))
				if found {
					token = cacheToken.(string)
				}
			}
			if userId == "" || token == "" {
				//登录
				client := http.Client{}

				req, err := http.NewRequest("POST", "https://spuckhogycrxcbomznwo.supabase.co/auth/v1/token?grant_type=password", strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s","gotrue_meta_security":{}}`, account, password)))
				if err == nil {
					req.Header.Set("content-type", "application/json")
					storageApiKey := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNwdWNraG9neWNyeGNib216bndvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDcyNDYwMzksImV4cCI6MjAyMjgyMjAzOX0.tvlGT7NZY8bijMjNIu1WhAtPnSKuDeYhtveo4DRt6xg"
					req.Header.Set("apikey", storageApiKey)
					req.Header.Set("authorization", "Bearer "+storageApiKey)
					req.Header.Set("origin", "https://chat.notdiamond.ai")
					req.Header.Set("referer", "https://chat.notdiamond.ai/")
					req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
					req.Header.Set("x-client-info", "supabase-ssr/0.4.0")
					req.Header.Set("x-supabase-api-version", "2024-01-01")

					res, err := client.Do(req)
					defer res.Body.Close()
					if err == nil {
						common.SysLog("notdiamond-登录成功")
						newBodyByte, err := io.ReadAll(res.Body)
						if err == nil {
							var input map[string]interface{}
							err := json.Unmarshal(newBodyByte, &input)
							if err == nil {
								token = "base64-" + base64.RawURLEncoding.EncodeToString(newBodyByte)
								tempUserId, ok := input["user"].(map[string]interface{})["id"]
								if ok {
									userId = tempUserId.(string)
								}
							}
						}
					}
				}

				if userId != "" && token != "" {
					if common.RedisEnabled {
						err = common.RedisSet(fmt.Sprintf("notdiamondUserId:%s", nextAction), userId, 12*time.Hour)
						if err != nil {
							common.SysError("Redis set notdiamondUserId error: " + err.Error())
						}
						err = common.RedisSet(fmt.Sprintf("notdiamondToken:%s", nextAction), token, 12*time.Hour)
						if err != nil {
							common.SysError("Redis set notdiamondToken error: " + err.Error())
						}
					} else {
						helpCache.HelpCacheSet(fmt.Sprintf("notdiamondUserId:%s", nextAction), userId, 12*60*60)
						helpCache.HelpCacheSet(fmt.Sprintf("notdiamondToken:%s", nextAction), token, 12*60*60)
					}
				}
			}
		}
	}
	data := map[string]string{
		"userId":     userId,
		"nextAction": nextAction,
		"token":      token,
		"mode":       mode,
	}
	return data
}

func ToNotdiamondBody(key string, requestBody io.Reader) string {
	keyData := InitNAccount(key)
	bodyBytes, _ := io.ReadAll(requestBody)
	bodyString := string(bodyBytes)
	var input map[string]interface{}
	err := json.Unmarshal([]byte(bodyString), &input)
	if err != nil {
		return string(bodyBytes)
	}
	input["user_id"] = keyData["userId"]
	cModel := input["model"].(string)
	delete(input, "model")
	switch cModel {
	case "gpt-4o":
		input["provider"] = map[string]string{
			"model":    "gpt-4o",
			"provider": "openai",
		}
	case "gpt-4o-mini":
		input["provider"] = map[string]string{
			"model":    "gpt-4o-mini",
			"provider": "openai",
		}
	case "gpt-4-turbo-2024-04-09":
		input["provider"] = map[string]string{
			"model":    "gpt-4-turbo-2024-04-09",
			"provider": "openai",
		}
	case "claude-3-5-sonnet-20240620":
		input["provider"] = map[string]string{
			"model":    "claude-3-5-sonnet-20240620",
			"provider": "anthropic",
		}
	case "claude-3-haiku-20240307":
		input["provider"] = map[string]string{
			"model":    "claude-3-haiku-20240307",
			"provider": "anthropic",
		}
	case "gemini-1.5-flash-latest":
		input["provider"] = map[string]string{
			"model":    "gemini-1.5-flash-latest",
			"provider": "google",
		}
	case "gemini-1.5-pro-latest":
		input["provider"] = map[string]string{
			"model":    "gemini-1.5-pro-latest",
			"provider": "google",
		}
	case "Meta-Llama-3.1-70B-Instruct-Turbo":
		input["provider"] = map[string]string{
			"model":    "Meta-Llama-3.1-70B-Instruct-Turbo",
			"provider": "togetherai",
		}
	case "Meta-Llama-3.1-405B-Instruct-Turbo":
		input["provider"] = map[string]string{
			"model":    "Meta-Llama-3.1-405B-Instruct-Turbo",
			"provider": "togetherai",
		}
	case "llama-3.1-sonar-large-128k-online":
		input["provider"] = map[string]string{
			"model":    "llama-3.1-sonar-large-128k-online",
			"provider": "perplexity",
		}
	case "mistral-large-2407":
		input["provider"] = map[string]string{
			"model":    "mistral-large-2407",
			"provider": "mistral",
		}
	}
	outputJSON, err := json.Marshal(input)
	if err != nil {
		return string(bodyBytes)
	}
	return string(outputJSON)
}

func GerBaseNHeader(c *http.Request, nextAction string, token string) {
	c.Header.Add("accept", "text/x-component")
	c.Header.Add("accept-language", "zh-CN,zh;q=0.6")
	c.Header.Add("next-action", nextAction)
	c.Header.Add("next-router-state-tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22(chat)%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D")
	c.Header.Add("Origin", "https://chat.notdiamond.ai")
	c.Header.Add("referer", "https://chat.notdiamond.ai/")
	c.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	c.Header.Add("Cookie", "sb-spuckhogycrxcbomznwo-auth-token="+token)
	c.Header.Add("content-type", "text/plain;charset=UTF-8")
	c.Header.Add("Host", "chat.notdiamond.ai")
	c.Header.Add("Connection", "keep-alive")
}

type NotdiamondData struct {
	Curr   string        `json:"curr,omitempty"`
	Next   string        `json:"next,omitempty"`
	Diff   []interface{} `json:"diff,omitempty"`
	Output struct {
		Curr string `json:"curr,omitempty"`
		Next string `json:"next,omitempty"`
		Type string `json:"type,omitempty"`
	} `json:"output,omitempty"`
}

func NotdiamondHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*dto.OpenAIErrorWithStatusCode, *dto.Usage) {
	account := InitNAccount(info.ApiKey)
	changeCookie := false
	for _, cookie := range resp.Cookies() {
		common.SysLog(cookie.Name + ": " + cookie.Value)
		if cookie.Name == "sb-spuckhogycrxcbomznwo-auth-token" && len(cookie.Value) > 1 {
			account["token"] = cookie.Value
			changeCookie = true
		}
	}
	if changeCookie {
		common.SysLog("notdiamond-刷新token")
		if account["mode"] == "token" {
			newApiKey := account["userId"] + "#" + account["nextAction"] + "#" + account["token"]
			common.SysLog(newApiKey)
			channel, err := model.GetChannelById(info.ChannelId, true)
			if err != nil {
			} else {
				channel.Key = newApiKey
				_ = channel.Save()
			}
		} else {
			common.SysLog(account["token"])
			if common.RedisEnabled {
				err := common.RedisSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*time.Hour)
				if err != nil {
					common.SysError("Redis set notdiamondToken error: " + err.Error())
				}
			} else {
				helpCache.HelpCacheSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*60*60)
			}
		}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	var respArr []string
	for scanner.Scan() {
		data := scanner.Text()
		common.SysLog(data)
		if len(data) < 1 {
			continue
		}
		splitStr := strings.SplitN(data, ":", 2)
		if len(splitStr) < 2 {
			continue
		}
		var cData NotdiamondData
		err := json.Unmarshal([]byte(splitStr[1]), &cData)
		if err != nil {
			continue
		}
		tempData := ""
		if cData.Curr != "" {
			tempData = cData.Curr
		} else if len(cData.Diff) > 1 {
			tempData = cData.Diff[1].(string)
		} else if cData.Output.Curr != "" {
			tempData = cData.Output.Curr
		}
		if len(tempData) > 0 {
			newStr := strings.Replace(tempData, "$$", "$", -1)
			respArr = append(respArr, newStr)
		}
	}
	err := resp.Body.Close()
	if err != nil {
		return service.OpenAIErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}
	if len(respArr) < 1 {
		return service.OpenAIErrorWrapper(err, "unmarshal_response_body_failed", http.StatusInternalServerError), nil
	}
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	createdTime := common.GetTimestamp()
	completionTokens, _ := service.CountTokenText(strings.Join(respArr, ""), info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	content, _ := json.Marshal(strings.Join(respArr, ""))
	choice := dto.OpenAITextResponseChoice{
		Index: 0,
		Message: dto.Message{
			Role:    "assistant",
			Content: content,
		},
		FinishReason: "stop",
	}

	fullTextResponse := dto.OpenAITextResponse{
		Id:      responseId,
		Object:  "chat.completion",
		Created: createdTime,
		Choices: []dto.OpenAITextResponseChoice{choice},
		Usage:   usage,
	}
	jsonResponse, err := json.Marshal(fullTextResponse)
	if err != nil {
		return service.OpenAIErrorWrapper(err, "marshal_response_body_failed", http.StatusInternalServerError), nil
	}
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)

	return nil, &usage
}

func NotdiamondStreamHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*dto.OpenAIErrorWithStatusCode, *dto.Usage) {
	account := InitNAccount(info.ApiKey)
	changeCookie := false
	for _, cookie := range resp.Cookies() {
		common.SysLog(cookie.Name + ": " + cookie.Value)
		if cookie.Name == "sb-spuckhogycrxcbomznwo-auth-token" && len(cookie.Value) > 1 {
			account["token"] = cookie.Value
			changeCookie = true
		}
	}
	if changeCookie {
		common.SysLog("notdiamond-刷新token")
		if account["mode"] == "token" {
			newApiKey := account["userId"] + "#" + account["nextAction"] + "#" + account["token"]
			common.SysLog(newApiKey)
			channel, err := model.GetChannelById(info.ChannelId, true)
			if err != nil {
			} else {
				channel.Key = newApiKey
				_ = channel.Save()
			}
		} else {
			common.SysLog(account["token"])
			if common.RedisEnabled {
				err := common.RedisSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*time.Hour)
				if err != nil {
					common.SysError("Redis set notdiamondToken error: " + err.Error())
				}
			} else {
				helpCache.HelpCacheSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*60*60)
			}
		}
	}

	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	var respArr []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	dataChan := make(chan string)
	stopChan := make(chan bool)
	go func() {
		for scanner.Scan() {
			data := scanner.Text()
			common.SysLog(data)
			if len(data) < 1 {
				continue
			}
			splitStr := strings.SplitN(data, ":", 2)
			if len(splitStr) < 2 {
				continue
			}
			var cData NotdiamondData
			err := json.Unmarshal([]byte(splitStr[1]), &cData)
			if err != nil {
				continue
			}
			tempData := ""
			if cData.Curr != "" {
				tempData = cData.Curr
			} else if len(cData.Diff) > 1 {
				tempData = cData.Diff[1].(string)
			} else if cData.Output.Curr != "" {
				tempData = cData.Output.Curr
			}
			if len(tempData) > 0 {
				newStr := strings.Replace(tempData, "$$", "$", -1)
				respArr = append(respArr, newStr)

				var choice dto.ChatCompletionsStreamResponseChoice
				choice.Delta.SetContentString(newStr)
				var responseTemp dto.ChatCompletionsStreamResponse
				responseTemp.Object = "chat.completion.chunk"
				responseTemp.Model = info.UpstreamModelName
				responseTemp.Choices = []dto.ChatCompletionsStreamResponseChoice{choice}
				responseTemp.Id = responseId
				responseTemp.Created = common.GetTimestamp()
				dataNew, err := json.Marshal(responseTemp)
				if err != nil {
					common.SysError("error marshalling stream response: " + err.Error())
					stopChan <- true
					return
				}
				dataChan <- string(dataNew)
			}
		}
		stopChan <- true
	}()
	service.SetEventStreamHeaders(c)
	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-dataChan:
			c.Render(-1, common.CustomEvent{Data: "data: " + data})
			return true
		case <-stopChan:
			c.Render(-1, common.CustomEvent{Data: "data: [DONE]"})
			return false
		}
	})
	err := resp.Body.Close()
	if err != nil {
		return service.OpenAIErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}
	completionTokens, _ := service.CountTokenText(strings.Join(respArr, ""), info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	return nil, &usage
}
