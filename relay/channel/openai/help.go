package openai

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"one-api/common"
	"one-api/dto"
	relaycommon "one-api/relay/common"
	"one-api/relay/helper"
	"one-api/service"
	"one-api/types"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

func GerBaseHeader(c *http.Header) {
	c.Set("accept", "*/*")
	c.Set("accept-language", "zh-CN,zh;q=0.9")
	c.Set("content-type", "application/json")
	c.Set("origin", "https://groq.com")
	c.Set("referer", "https://groq.com/")
	c.Set("sec-ch-ua", `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`)
	c.Set("sec-ch-ua-mobile", "?0")
	c.Set("sec-ch-ua-platform", `"Windows"`)
	c.Set("sec-fetch-dest", "empty")
	c.Set("sec-fetch-mode", "cors")
	c.Set("sec-fetch-site", "cross-site")
	c.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
}

func GerOrganizationId(apiKey string) string {
	client := http.Client{}

	req, err := http.NewRequest("GET", "https://api.groq.com/platform/v1/user/profile", nil)
	if err != nil {
		return ""
	}
	GerBaseHeader(&req.Header)
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
	GerBaseHeader(&req.Header)
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
			if strings.Contains(token, "base64-") {
				token = ""
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
								token = input["access_token"].(string)
								//base64.RawURLEncoding.EncodeToString(newBodyByte)
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
						err = common.RedisSet(fmt.Sprintf("notdiamondUserId:%s", nextAction), userId, 50*time.Minute)
						if err != nil {
							common.SysError("Redis set notdiamondUserId error: " + err.Error())
						}
						err = common.RedisSet(fmt.Sprintf("notdiamondToken:%s", nextAction), token, 50*time.Minute)
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
	case "gpt-4-turbo-2024-04-09":
		input["provider"] = map[string]string{
			"model":    "gpt-4-turbo-2024-04-09",
			"provider": "openai",
		}
	case "gpt-4o-mini":
		input["provider"] = map[string]string{
			"model":    "gpt-4o-mini",
			"provider": "openai",
		}
	case "chatgpt-4o-latest":
		input["provider"] = map[string]string{
			"model":    "chatgpt-4o-latest",
			"provider": "openai",
		}
	case "claude-3-5-sonnet-20241022":
		input["provider"] = map[string]string{
			"model":    "anthropic.claude-3-5-sonnet-20241022-v2:0",
			"provider": "anthropic",
		}
	case "claude-3-5-haiku-20241022":
		input["provider"] = map[string]string{
			"model":    "anthropic.claude-3-5-haiku-20241022-v1:0",
			"provider": "anthropic",
		}
	case "gemini-1.5-flash-latest":
		input["provider"] = map[string]string{
			"model":    "models/gemini-1.5-flash-latest",
			"provider": "google",
		}
	case "gemini-1.5-pro-latest":
		input["provider"] = map[string]string{
			"model":    "models/gemini-1.5-pro-latest",
			"provider": "google",
		}
	case "Meta-Llama-3.1-70B-Instruct-Turbo":
		input["provider"] = map[string]string{
			"model":    "meta.llama3-1-70b-instruct-v1:0",
			"provider": "togetherai",
		}
	//case "Meta-Llama-3.1-405B-Instruct-Turbo":
	//	input["provider"] = map[string]string{
	//		"model":    "Meta-Llama-3.1-405B-Instruct-Turbo",
	//		"provider": "togetherai",
	//	}
	case "llama-3.1-sonar-large-128k-online":
		input["provider"] = map[string]string{
			"model":    "llama-3.1-sonar-large-128k-online",
			"provider": "perplexity",
		}
	case "mistral-large-2407":
		input["provider"] = map[string]string{
			"model":    "mistral.mistral-large-2407-v1:0",
			"provider": "mistral",
		}
	}
	outputJSON, err := json.Marshal(input)
	if err != nil {
		return string(bodyBytes)
	}
	return string(outputJSON)
}

func GerBaseNHeader(c *http.Header, nextAction string, token string) {
	c.Add("accept", "*/*")
	//c.Header.Add("accept-language", "zh-CN,zh;q=0.6")
	//c.Header.Add("next-action", nextAction)
	//c.Header.Add("next-router-state-tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22(chat)%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D")
	c.Add("Origin", "https://chat.notdiamond.ai")
	c.Add("referer", "https://chat.notdiamond.ai/")
	c.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	//c.Header.Add("Cookie", "sb-spuckhogycrxcbomznwo-auth-token="+token)
	c.Add("Authorization", "Bearer "+token)
	//c.Header.Add("content-type", "application/json")
	//c.Header.Add("Host", "chat.notdiamond.ai")
	//c.Header.Add("Connection", "keep-alive")
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

func NotdiamondHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	//account := InitNAccount(info.ApiKey)
	//changeCookie := false
	//for _, cookie := range resp.Cookies() {
	//	common.SysLog(cookie.Name + ": " + cookie.Value)
	//	if cookie.Name == "sb-spuckhogycrxcbomznwo-auth-token" && len(cookie.Value) > 1 {
	//		account["token"] = cookie.Value
	//		changeCookie = true
	//	}
	//}
	//if changeCookie {
	//	common.SysLog("notdiamond-刷新token")
	//	if account["mode"] == "token" {
	//		newApiKey := account["userId"] + "#" + account["nextAction"] + "#" + account["token"]
	//		common.SysLog(newApiKey)
	//		channel, err := model.GetChannelById(info.ChannelId, true)
	//		if err != nil {
	//		} else {
	//			channel.Key = newApiKey
	//			_ = channel.Save()
	//		}
	//	} else {
	//		common.SysLog(account["token"])
	//		if common.RedisEnabled {
	//			err := common.RedisSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*time.Hour)
	//			if err != nil {
	//				common.SysError("Redis set notdiamondToken error: " + err.Error())
	//			}
	//		} else {
	//			helpCache.HelpCacheSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*60*60)
	//		}
	//	}
	//}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	var respArr []string
	for scanner.Scan() {
		data := scanner.Text()
		data += "\n"
		common.SysLog(data)
		respArr = append(respArr, data)
		//if len(data) < 1 {
		//	continue
		//}
		//splitStr := strings.SplitN(data, ":", 2)
		//if len(splitStr) < 2 {
		//	continue
		//}
		//var cData NotdiamondData
		//err := json.Unmarshal([]byte(splitStr[1]), &cData)
		//if err != nil {
		//	continue
		//}
		//tempData := ""
		//if cData.Curr != "" {
		//	tempData = cData.Curr
		//} else if len(cData.Diff) > 1 {
		//	tempData = cData.Diff[1].(string)
		//} else if cData.Output.Curr != "" {
		//	tempData = cData.Output.Curr
		//}
		//if len(tempData) > 0 {
		//	newStr := strings.Replace(tempData, "$$", "$", -1)
		//	respArr = append(respArr, newStr)
		//}
	}
	err := resp.Body.Close()
	if err != nil {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "close_response_body_failed",
			Type:    "notdiamond_error",
			Param:   "",
			Code:    "close_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	if len(respArr) < 1 {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "unmarshal_response_body_failed",
			Type:    "notdiamond_error",
			Param:   "",
			Code:    "unmarshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	createdTime := common.GetTimestamp()
	completionTokens := service.CountTextToken(strings.Join(respArr, ""), info.UpstreamModelName)
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
		return types.WithOpenAIError(types.OpenAIError{
			Message: "marshal_response_body_failed",
			Type:    "notdiamond_error",
			Param:   "",
			Code:    "marshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)

	return nil, &usage
}

func NotdiamondStreamHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	//account := InitNAccount(info.ApiKey)
	//changeCookie := false
	//for _, cookie := range resp.Cookies() {
	//	common.SysLog(cookie.Name + ": " + cookie.Value)
	//	if cookie.Name == "sb-spuckhogycrxcbomznwo-auth-token" && len(cookie.Value) > 1 {
	//		account["token"] = cookie.Value
	//		changeCookie = true
	//	}
	//}
	//if changeCookie {
	//	common.SysLog("notdiamond-刷新token")
	//	if account["mode"] == "token" {
	//		newApiKey := account["userId"] + "#" + account["nextAction"] + "#" + account["token"]
	//		common.SysLog(newApiKey)
	//		channel, err := model.GetChannelById(info.ChannelId, true)
	//		if err != nil {
	//		} else {
	//			channel.Key = newApiKey
	//			_ = channel.Save()
	//		}
	//	} else {
	//		common.SysLog(account["token"])
	//		if common.RedisEnabled {
	//			err := common.RedisSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*time.Hour)
	//			if err != nil {
	//				common.SysError("Redis set notdiamondToken error: " + err.Error())
	//			}
	//		} else {
	//			helpCache.HelpCacheSet(fmt.Sprintf("notdiamondToken:%s", account["nextAction"]), account["token"], 12*60*60)
	//		}
	//	}
	//}

	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	var respArr []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	dataChan := make(chan string)
	stopChan := make(chan bool)
	gopool.Go(func() {
		for scanner.Scan() {
			data := scanner.Text()
			data += "\n"
			common.SysLog(data)
			respArr = append(respArr, data)

			var choice dto.ChatCompletionsStreamResponseChoice
			choice.Delta.SetContentString(data)
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

			//if len(data) < 1 {
			//	continue
			//}
			//splitStr := strings.SplitN(data, ":", 2)
			//if len(splitStr) < 2 {
			//	continue
			//}
			//var cData NotdiamondData
			//err := json.Unmarshal([]byte(splitStr[1]), &cData)
			//if err != nil {
			//	continue
			//}
			//tempData := ""
			//if cData.Curr != "" {
			//	tempData = cData.Curr
			//} else if len(cData.Diff) > 1 {
			//	tempData = cData.Diff[1].(string)
			//} else if cData.Output.Curr != "" {
			//	tempData = cData.Output.Curr
			//}
			//if len(tempData) > 0 {
			//	newStr := strings.Replace(tempData, "$$", "$", -1)
			//	respArr = append(respArr, newStr)
			//
			//	var choice dto.ChatCompletionsStreamResponseChoice
			//	choice.Delta.SetContentString(newStr)
			//	var responseTemp dto.ChatCompletionsStreamResponse
			//	responseTemp.Object = "chat.completion.chunk"
			//	responseTemp.Model = info.UpstreamModelName
			//	responseTemp.Choices = []dto.ChatCompletionsStreamResponseChoice{choice}
			//	responseTemp.Id = responseId
			//	responseTemp.Created = common.GetTimestamp()
			//	dataNew, err := json.Marshal(responseTemp)
			//	if err != nil {
			//		common.SysError("error marshalling stream response: " + err.Error())
			//		stopChan <- true
			//		return
			//	}
			//	dataChan <- string(dataNew)
			//}
		}
		stopChan <- true
	})
	helper.SetEventStreamHeaders(c)
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
		return types.WithOpenAIError(types.OpenAIError{
			Message: "close_response_body_failed",
			Type:    "notdiamond_error",
			Param:   "",
			Code:    "close_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	completionTokens := service.CountTextToken(strings.Join(respArr, ""), info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	return nil, &usage
}

// GetMerlin Start
type OpenAIRequest struct {
	Messages []Message `json:"messages"`
	//Stream   bool      `json:"stream"`
	Model string `json:"model"`
}
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type MerlinRequest struct {
	Attachments []interface{} `json:"attachments"`
	ChatId      string        `json:"chatId"`
	Language    string        `json:"language"`
	Message     struct {
		Content  string `json:"content"`
		Context  string `json:"context"`
		ChildId  string `json:"childId"`
		Id       string `json:"id"`
		ParentId string `json:"parentId"`
	} `json:"message"`
	Metadata struct {
		LargeContext  bool `json:"largeContext"`
		MerlinMagic   bool `json:"merlinMagic"`
		ProFinderMode bool `json:"proFinderMode"`
		WebAccess     bool `json:"webAccess"`
	} `json:"metadata"`
	Mode  string `json:"mode"`
	Model string `json:"model"`
}
type MerlinResponse struct {
	Data struct {
		Content string `json:"content"`
	} `json:"data"`
}
type GetMerlinTokenResponse struct {
	IdToken string `json:"idToken"`
}

func generateUUID() string {
	return uuid.New().String()
}

func generateV1UUID() string {
	uuidObj := uuid.Must(uuid.NewUUID())
	return uuidObj.String()
}

func GetMerlinToken(key string) string {
	var apiKey, uid string
	if strings.Contains(key, "#") {
		splitStr := strings.Split(key, "#")
		if len(splitStr) == 2 {
			apiKey = splitStr[0]
			uid = splitStr[1]
		}
	} else {
		apiKey = key
		uid = "4e75acce-a57e-4eda-a5c7-931d9f461fb8"
	}

	var token string
	keyMd5 := getMd5String(key)
	if common.RedisEnabled {
		var err error
		token, err = common.RedisGet(fmt.Sprintf("GetMerlinToken:%s", keyMd5))
		if err != nil {
			token = ""
		}
	}
	if token == "" {
		tokenReq := struct {
			UUID string `json:"uuid"`
		}{
			UUID: uid,
		}
		tokenReqBody, _ := json.Marshal(tokenReq)
		common.SysLog(string(tokenReqBody))
		resp, err := http.Post(
			"https://getmerlin-main-server.vercel.app/generate",
			"application/json",
			strings.NewReader(string(tokenReqBody)),
		)
		defer resp.Body.Close()
		if err == nil {
			var tokenResp GetMerlinTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			if err == nil {
				token = tokenResp.IdToken
			}
		}
	}
	if token == "" {
		url := "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + apiKey
		method := "POST"
		payload := strings.NewReader(`{"returnSecureToken": true}`)
		client := &http.Client{}
		req, err := http.NewRequest(method, url, payload)
		if err != nil {
			token = ""
		}
		req.Header.Add("accept", "*/*")
		//req.Header.Add("accept-language", "zh-CN,zh;q=0.8")
		req.Header.Add("origin", "https://www.getmerlin.in")
		req.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
		req.Header.Add("content-type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			token = ""
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		common.SysLog("GetMerlinTokenBody：" + bodyString)

		var input map[string]interface{}
		err = json.Unmarshal(bodyBytes, &input)
		if err == nil {
			token = input["idToken"].(string)
		}
	}
	if token != "" && common.RedisEnabled {
		err := common.RedisSet(fmt.Sprintf("GetMerlinToken:%s", keyMd5), token, 3*time.Minute)
		if err != nil {
			common.SysError("Redis set token error: " + err.Error())
		}
	}

	return token
}

func GetMerlinBaseHeader(c *http.Header, token string) {
	c.Set("Content-Type", "application/json")
	c.Set("Accept", "text/event-stream, text/event-stream")
	c.Set("Authorization", "Bearer "+token)
	c.Set("x-merlin-version", "web-merlin")
	//c.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	c.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	c.Set("host", "arcane.getmerlin.in")
	c.Set("origin", "https://www.getmerlin.in")
	c.Set("referer", "https://www.getmerlin.in/")
}

func ToGetMerlinReq(requestBody io.Reader) string {
	var openAIReq OpenAIRequest
	bodyBytes, _ := io.ReadAll(requestBody)
	bodyString := string(bodyBytes)
	if err := json.Unmarshal(bodyBytes, &openAIReq); err != nil {
		return ""
	}
	var contextMessages []string
	for i := 0; i < len(openAIReq.Messages)-1; i++ {
		msg := openAIReq.Messages[i]
		contextMessages = append(contextMessages, fmt.Sprintf("%s: %s", msg.Role, msg.Content))
	}
	context := strings.Join(contextMessages, "\n")
	merlinReq := MerlinRequest{
		Attachments: make([]interface{}, 0),
		ChatId:      generateV1UUID(),
		Language:    "AUTO",
		Message: struct {
			Content  string `json:"content"`
			Context  string `json:"context"`
			ChildId  string `json:"childId"`
			Id       string `json:"id"`
			ParentId string `json:"parentId"`
		}{
			Content:  openAIReq.Messages[len(openAIReq.Messages)-1].Content,
			Context:  context,
			ChildId:  generateUUID(),
			Id:       generateUUID(),
			ParentId: "root",
		},
		Mode:  "UNIFIED_CHAT",
		Model: openAIReq.Model,
		Metadata: struct {
			LargeContext  bool `json:"largeContext"`
			MerlinMagic   bool `json:"merlinMagic"`
			ProFinderMode bool `json:"proFinderMode"`
			WebAccess     bool `json:"webAccess"`
		}{
			LargeContext:  false,
			MerlinMagic:   false,
			ProFinderMode: false,
			WebAccess:     false,
		},
	}
	outputJSON, err := json.Marshal(merlinReq)
	if err != nil {
		return bodyString
	}
	return string(outputJSON)
}

func GetMerlinStreamHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	var respArr []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	dataChan := make(chan string)
	stopChan := make(chan bool)
	gopool.Go(func() {
		for scanner.Scan() {
			info.SetFirstResponseTime()
			data := scanner.Text()
			dataLine := strings.TrimSpace(data)
			common.SysLog(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				var merlinResp MerlinResponse
				_ = json.Unmarshal([]byte(strings.TrimPrefix(dataLine, "data: ")), &merlinResp)
				if merlinResp.Data.Content != "" {
					respArr = append(respArr, merlinResp.Data.Content)
					var choice dto.ChatCompletionsStreamResponseChoice
					choice.Delta.SetContentString(merlinResp.Data.Content)
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
		}
		stopChan <- true
	})
	helper.SetEventStreamHeaders(c)
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
		return types.WithOpenAIError(types.OpenAIError{
			Message: "close_response_body_failed",
			Type:    "merlin_error",
			Param:   "",
			Code:    "close_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	allContent := strings.Join(respArr, "")
	if allContent == "" {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "unmarshal_response_body_failed",
			Type:    "merlin_error",
			Param:   "",
			Code:    "unmarshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	completionTokens := service.CountTextToken(allContent, info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	return nil, &usage
}

func GetMerlinHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	var respArr []string
	for scanner.Scan() {
		info.SetFirstResponseTime()
		data := scanner.Text()
		dataLine := strings.TrimSpace(data)
		common.SysLog(dataLine)
		if strings.HasPrefix(dataLine, "data: ") {
			var merlinResp MerlinResponse
			_ = json.Unmarshal([]byte(strings.TrimPrefix(dataLine, "data: ")), &merlinResp)
			if merlinResp.Data.Content != "" {
				respArr = append(respArr, merlinResp.Data.Content)
			}
		}
	}
	err := resp.Body.Close()
	if err != nil {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "close_response_body_failed",
			Type:    "merlin_error",
			Param:   "",
			Code:    "close_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	if len(respArr) < 1 {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "unmarshal_response_body_failed",
			Type:    "merlin_error",
			Param:   "",
			Code:    "unmarshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	createdTime := common.GetTimestamp()
	completionTokens := service.CountTextToken(strings.Join(respArr, ""), info.UpstreamModelName)
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
		return types.WithOpenAIError(types.OpenAIError{
			Message: "marshal_response_body_failed",
			Type:    "merlin_error",
			Param:   "",
			Code:    "marshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)

	return nil, &usage
}

//GetMerlin End

func GenZaiHeader(c *http.Header, info *relaycommon.RelayInfo) {
	if info.ApiKey == "zai" {
		info.ApiKey, _ = getZaiAnonymousToken()
	}
	c.Set("Content-Type", "application/json")
	c.Set("Accept", "application/json, text/event-stream")
	c.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	c.Set("Authorization", "Bearer "+info.ApiKey)
	c.Set("Accept-Language", "zh-CN")
	c.Set("sec-ch-ua", "\"Not;A=Brand\";v=\"99\", \"Microsoft Edge\";v=\"140\", \"Chromium\";v=\"140\"")
	c.Set("sec-ch-ua-mobile", "?0")
	c.Set("sec-ch-ua-platform", "\"Windows\"")
	c.Set("X-FE-Version", "prod-fe-1.0.70")
	c.Set("Origin", "https://chat.z.ai")
	chatID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
	c.Set("Referer", "https://chat.z.ai/c/"+chatID)
}

// 获取匿名token（每次对话使用不同token，避免共享记忆）
func getZaiAnonymousToken() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://chat.z.ai/api/v1/auths/", nil)
	if err != nil {
		return "", err
	}
	// 伪装浏览器头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("X-FE-Version", "prod-fe-1.0.70")
	req.Header.Set("sec-ch-ua", "\"Not;A=Brand\";v=\"99\", \"Microsoft Edge\";v=\"140\", \"Chromium\";v=\"140\"")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Set("Origin", "https://chat.z.ai")
	req.Header.Set("Referer", "https://chat.z.ai/")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anon token status=%d", resp.StatusCode)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token == "" {
		return "", fmt.Errorf("anon token empty")
	}
	return body.Token, nil
}

// getChineseWeekday 返回中文星期几
func getChineseWeekday(weekday time.Weekday) string {
	weekdays := map[time.Weekday]string{
		time.Sunday:    "星期日",
		time.Monday:    "星期一",
		time.Tuesday:   "星期二",
		time.Wednesday: "星期三",
		time.Thursday:  "星期四",
		time.Friday:    "星期五",
		time.Saturday:  "星期六",
	}
	return weekdays[weekday]
}

// ModelZaiConfig 模型配置结构
type ModelZaiConfig struct {
	ID            string                 `json:"id"`            // OpenAI API中的模型ID
	Name          string                 `json:"name"`          // 显示名称
	UpstreamID    string                 `json:"upstreamId"`    // Z.ai上游的模型ID
	Capabilities  ModelZaiCapabilities   `json:"capabilities"`  // 模型能力
	DefaultParams map[string]interface{} `json:"defaultParams"` // 默认参数
}

// ModelZaiCapabilities 模型能力配置
type ModelZaiCapabilities struct {
	Vision   bool `json:"vision"`   // 视觉能力
	MCP      bool `json:"mcp"`      // MCP能力
	Thinking bool `json:"thinking"` // 思考能力
}

// SUPPORTED_Z_MODELS 支持的模型配置
var SUPPORTED_Z_MODELS = []ModelZaiConfig{
	{
		ID:         "0727-360B-API",
		Name:       "GLM-4.5",
		UpstreamID: "0727-360B-API",
		Capabilities: ModelZaiCapabilities{
			Vision:   false,
			MCP:      true,
			Thinking: true,
		},
		DefaultParams: map[string]interface{}{
			"top_p":       0.95,
			"temperature": 0.6,
			"max_tokens":  80000,
		},
	},
	{
		ID:         "glm-4.5v",
		Name:       "GLM-4.5V",
		UpstreamID: "glm-4.5v",
		Capabilities: ModelZaiCapabilities{
			Vision:   true,
			MCP:      false,
			Thinking: true,
		},
		DefaultParams: map[string]interface{}{
			"top_p":       0.6,
			"temperature": 0.8,
		},
	},
}

// getZaiModelConfig 根据模型ID获取配置
func getZaiModelConfig(modelID string) *ModelZaiConfig {
	// 标准化模型ID
	normalizedModelID := normalizeZaiModelID(modelID)

	for _, model := range SUPPORTED_Z_MODELS {
		if model.ID == normalizedModelID {
			return &model
		}
	}

	// 如果未找到，返回默认模型
	if len(SUPPORTED_Z_MODELS) > 0 {
		return &SUPPORTED_Z_MODELS[0]
	}

	return nil
}

// normalizeZaiModelID 标准化模型ID，处理不同客户端的命名差异
func normalizeZaiModelID(modelID string) string {
	normalized := strings.ToLower(strings.TrimSpace(modelID))

	// 处理常见的模型ID映射
	modelMappings := map[string]string{
		"glm-4.5v":             "glm-4.5v",
		"glm4.5v":              "glm-4.5v",
		"glm_4.5v":             "glm-4.5v",
		"gpt-4-vision-preview": "glm-4.5v", // 向后兼容
		"0727-360b-api":        "0727-360B-API",
		"glm-4.5":              "0727-360B-API",
		"glm4.5":               "0727-360B-API",
		"glm_4.5":              "0727-360B-API",
		"gpt-4":                "0727-360B-API", // 向后兼容
	}

	if mapped, exists := modelMappings[normalized]; exists {
		return mapped
	}

	return normalized
}

// processZaiMessageContent 处理消息内容，支持多模态内容检测和模型能力检查
func processZaiMessageContent(content interface{}, modelConfig *ModelZaiConfig) interface{} {
	// 检查是否为多模态消息（数组格式）
	if contentArray, ok := content.([]interface{}); ok {
		// 验证模型是否支持多模态
		if !modelConfig.Capabilities.Vision {
			// 模型不支持多模态，只保留文本内容
			var textParts []string
			for _, block := range contentArray {
				if blockMap, ok := block.(map[string]interface{}); ok {
					if blockType, exists := blockMap["type"]; exists && blockType == "text" {
						if text, exists := blockMap["text"]; exists {
							if textStr, ok := text.(string); ok {
								textParts = append(textParts, textStr)
							}
						}
					}
				}
			}
			// 将文本内容合并为字符串
			if len(textParts) > 0 {
				return strings.Join(textParts, "\n")
			}
			return ""
		}

		// 模型支持多模态，处理所有内容类型
		var processedBlocks []interface{}
		for _, block := range contentArray {
			if blockMap, ok := block.(map[string]interface{}); ok {
				blockType, _ := blockMap["type"].(string)
				switch blockType {
				case "text":
					// 保留文本内容
					processedBlocks = append(processedBlocks, block)
				case "image_url":
					// 检查图像URL是否有效
					if imageUrl, exists := blockMap["image_url"]; exists {
						if imageUrlMap, ok := imageUrl.(map[string]interface{}); ok {
							if url, exists := imageUrlMap["url"]; exists {
								if urlStr, ok := url.(string); ok && urlStr != "" {
									processedBlocks = append(processedBlocks, block)
								}
							}
						}
					}
				case "video_url":
					// 检查视频URL是否有效
					if videoUrl, exists := blockMap["video_url"]; exists {
						if videoUrlMap, ok := videoUrl.(map[string]interface{}); ok {
							if url, exists := videoUrlMap["url"]; exists {
								if urlStr, ok := url.(string); ok && urlStr != "" {
									processedBlocks = append(processedBlocks, block)
								}
							}
						}
					}
				case "document_url":
					// 检查文档URL是否有效
					if docUrl, exists := blockMap["document_url"]; exists {
						if docUrlMap, ok := docUrl.(map[string]interface{}); ok {
							if url, exists := docUrlMap["url"]; exists {
								if urlStr, ok := url.(string); ok && urlStr != "" {
									processedBlocks = append(processedBlocks, block)
								}
							}
						}
					}
				case "audio_url":
					// 检查音频URL是否有效
					if audioUrl, exists := blockMap["audio_url"]; exists {
						if audioUrlMap, ok := audioUrl.(map[string]interface{}); ok {
							if url, exists := audioUrlMap["url"]; exists {
								if urlStr, ok := url.(string); ok && urlStr != "" {
									processedBlocks = append(processedBlocks, block)
								}
							}
						}
					}
				default:
					// 保留其他类型的内容块
					processedBlocks = append(processedBlocks, block)
				}
			}
		}
		return processedBlocks
	}

	// 非多模态消息，直接返回原内容
	return content
}

func GenZaiBody(requestBody io.Reader, info *relaycommon.RelayInfo) io.Reader {
	bodyBytes, _ := io.ReadAll(requestBody)

	var requestMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &requestMap); err != nil {
		// 如果解析失败，返回原始请求体
		return bytes.NewReader(bodyBytes)
	}

	// 从 HeadersOverride 中的 Referer 提取 chatID
	var chatID string
	if info.HeadersOverride != nil {
		if refererValue, exists := info.HeadersOverride["Referer"]; exists {
			if refererStr, ok := refererValue.(string); ok {
				// 从 Referer 中提取 chatID，格式如: https://chat.z.ai/c/{chatID}
				if strings.Contains(refererStr, "/c/") {
					parts := strings.Split(refererStr, "/c/")
					if len(parts) > 1 {
						chatID = parts[1]
					}
				}
			}
		}
	}
	// 如果没有从 Referer 中提取到 chatID，则生成新的
	if chatID == "" {
		chatID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
	}

	msgID := fmt.Sprintf("%d", time.Now().UnixNano())

	// 获取模型配置
	var modelConfig *ModelZaiConfig
	if modelVal, ok := requestMap["model"]; ok {
		if modelStr, ok := modelVal.(string); ok {
			modelConfig = getZaiModelConfig(modelStr)
		}
	}

	// 如果没有找到模型配置，使用默认模型
	if modelConfig == nil {
		modelConfig = &SUPPORTED_Z_MODELS[0]
	}

	// 处理消息
	var messages []map[string]interface{}
	if messagesVal, ok := requestMap["messages"]; ok {
		if messagesArray, ok := messagesVal.([]interface{}); ok {
			for _, msgVal := range messagesArray {
				if msgMap, ok := msgVal.(map[string]interface{}); ok {
					// 构造消息对象
					message := map[string]interface{}{
						"role": msgMap["role"],
					}

					// 处理content字段 - 支持字符串或数组格式，参考processMessages逻辑
					if content, exists := msgMap["content"]; exists {
						processedContent := processZaiMessageContent(content, modelConfig)
						message["content"] = processedContent
					}

					messages = append(messages, message)
				}
			}
		}
	}

	// 决定是否启用思考功能 - 优先使用请求参数，否则使用模型默认配置
	enableThinking := modelConfig.Capabilities.Thinking
	if thinkingVal, ok := requestMap["enable_thinking"]; ok {
		if thinkingBool, ok := thinkingVal.(bool); ok {
			enableThinking = thinkingBool
		}
	}

	// 构造上游请求体
	upstreamReq := map[string]interface{}{
		"stream":   true,
		"chat_id":  chatID,
		"id":       msgID,
		"model":    modelConfig.UpstreamID,
		"messages": messages,
		"params":   modelConfig.DefaultParams,
		"features": map[string]interface{}{
			"enable_thinking":  enableThinking,
			"image_generation": false,
			"web_search":       false,
			"auto_web_search":  false,
			"preview_mode":     modelConfig.Capabilities.Vision,
		},
		"background_tasks": map[string]bool{
			"title_generation": false,
			"tags_generation":  false,
		},
		"tool_servers": []string{},
		"variables": map[string]string{
			"{{USER_NAME}}":        fmt.Sprintf("Guest-%d", time.Now().UnixNano()/1e6),
			"{{USER_LOCATION}}":    "Unknown",
			"{{CURRENT_DATETIME}}": time.Now().Format("2006-01-02 15:04:05"),
			"{{CURRENT_DATE}}":     time.Now().Format("2006-01-02"),
			"{{CURRENT_TIME}}":     time.Now().Format("15:04:05"),
			"{{CURRENT_WEEKDAY}}":  getChineseWeekday(time.Now().Weekday()),
			"{{CURRENT_TIMEZONE}}": "Asia/Shanghai",
			"{{USER_LANGUAGE}}":    "zh-CN",
		},
	}

	// 根据模型配置设置 mcp_servers
	if modelConfig.Capabilities.MCP {
		upstreamReq["mcp_servers"] = []string{}
	}

	// 构建 model_item - 检查模型是否在支持列表中
	modelExists := false
	for _, supportedModel := range SUPPORTED_Z_MODELS {
		if supportedModel.ID == modelConfig.ID {
			modelExists = true
			break
		}
	}

	if modelExists {
		// 模型存在，构建完整的 model_item
		description := "Most advanced model, proficient in coding and tool use"
		if modelConfig.Capabilities.Vision {
			description = "Advanced visual understanding and analysis"
		}

		upstreamReq["model_item"] = map[string]interface{}{
			"id":       modelConfig.UpstreamID,
			"name":     modelConfig.Name,
			"owned_by": "openai",
			"openai": map[string]interface{}{
				"id":       modelConfig.UpstreamID,
				"name":     modelConfig.UpstreamID,
				"owned_by": "openai",
				"openai": map[string]interface{}{
					"id": modelConfig.UpstreamID,
				},
				"urlIdx": 1,
			},
			"urlIdx": 1,
			"info": map[string]interface{}{
				"id":            modelConfig.UpstreamID,
				"user_id":       "api-user",
				"base_model_id": nil,
				"name":          modelConfig.Name,
				"params":        modelConfig.DefaultParams,
				"meta": map[string]interface{}{
					"profile_image_url": "/static/favicon.png",
					"description":       description,
					"capabilities": map[string]interface{}{
						"vision":             modelConfig.Capabilities.Vision,
						"citations":          false,
						"preview_mode":       modelConfig.Capabilities.Vision,
						"web_search":         false,
						"language_detection": false,
						"restore_n_source":   false,
						"mcp":                modelConfig.Capabilities.MCP,
						"file_qa":            modelConfig.Capabilities.MCP,
						"returnFc":           true,
						"returnThink":        modelConfig.Capabilities.Thinking,
						"think":              modelConfig.Capabilities.Thinking,
					},
				},
			},
		}
	} else {
		// 模型不存在，只包含基本信息
		upstreamReq["model_item"] = map[string]interface{}{
			"id":       modelConfig.UpstreamID,
			"name":     modelConfig.Name,
			"owned_by": "openai",
		}
	}

	// 序列化为JSON
	upstreamBytes, err := json.Marshal(upstreamReq)
	if err != nil {
		// 如果序列化失败，返回原始请求体
		return bytes.NewReader(bodyBytes)
	}

	return bytes.NewReader(upstreamBytes)
}

func ZaiStreamHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	var respArr []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	dataChan := make(chan string)
	stopChan := make(chan bool)

	// 思考内容处理策略
	transformThinking := func(s string) string {
		// 去除 <summary>…</summary>
		re := regexp.MustCompile(`(?s)<summary>.*?</summary>`)
		s = re.ReplaceAllString(s, "")
		// 清理残留自定义标签
		s = strings.ReplaceAll(s, "</thinking>", "")
		s = strings.ReplaceAll(s, "<Full>", "")
		s = strings.ReplaceAll(s, "</Full>", "")
		s = strings.TrimSpace(s)

		// 根据策略处理 <details> 标签
		switch "strip" { // 对应 THINK_TAGS_MODE
		case "think":
			re := regexp.MustCompile(`<details[^>]*>`)
			s = re.ReplaceAllString(s, "<think>")
			s = strings.ReplaceAll(s, "</details>", "</think>")
		case "strip":
			re := regexp.MustCompile(`<details[^>]*>`)
			s = re.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, "</details>", "")
		}

		// 处理每行前缀 "> "
		s = strings.TrimPrefix(s, "> ")
		s = strings.ReplaceAll(s, "\n> ", "\n")
		return strings.TrimSpace(s)
	}

	gopool.Go(func() {
		for scanner.Scan() {
			info.SetFirstResponseTime()
			data := scanner.Text()
			dataLine := strings.TrimSpace(data)
			common.SysLog(dataLine)

			if strings.HasPrefix(dataLine, "data: ") {
				dataStr := strings.TrimPrefix(dataLine, "data: ")
				if dataStr == "" {
					continue
				}

				// 解析上游SSE数据
				var upstreamData struct {
					Type string `json:"type"`
					Data struct {
						DeltaContent string `json:"delta_content"`
						Phase        string `json:"phase"`
						Done         bool   `json:"done"`
						Usage        struct {
							PromptTokens     int `json:"prompt_tokens"`
							CompletionTokens int `json:"completion_tokens"`
							TotalTokens      int `json:"total_tokens"`
						} `json:"usage,omitempty"`
						Error *struct {
							Detail string `json:"detail"`
							Code   int    `json:"code"`
						} `json:"error,omitempty"`
						Inner *struct {
							Error *struct {
								Detail string `json:"detail"`
								Code   int    `json:"code"`
							} `json:"error,omitempty"`
						} `json:"data,omitempty"`
					} `json:"data"`
					Error *struct {
						Detail string `json:"detail"`
						Code   int    `json:"code"`
					} `json:"error,omitempty"`
				}

				err := json.Unmarshal([]byte(dataStr), &upstreamData)
				if err != nil {
					common.SysLog("SSE数据解析失败: " + err.Error())
					continue
				}

				// 错误检测
				if upstreamData.Error != nil || upstreamData.Data.Error != nil ||
					(upstreamData.Data.Inner != nil && upstreamData.Data.Inner.Error != nil) {
					errObj := upstreamData.Error
					if errObj == nil {
						errObj = upstreamData.Data.Error
					}
					if errObj == nil && upstreamData.Data.Inner != nil {
						errObj = upstreamData.Data.Inner.Error
					}
					common.SysLog(fmt.Sprintf("上游错误: code=%d, detail=%s", errObj.Code, errObj.Detail))
					stopChan <- true
					return
				}

				// 处理内容
				if upstreamData.Data.DeltaContent != "" {
					out := upstreamData.Data.DeltaContent
					if upstreamData.Data.Phase == "thinking" {
						out = transformThinking(out)
					}

					if out != "" {
						respArr = append(respArr, out)
						var choice dto.ChatCompletionsStreamResponseChoice
						choice.Delta.SetContentString(out)
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

				// 检查是否结束
				if upstreamData.Data.Done || upstreamData.Data.Phase == "done" {
					stopChan <- true
					return
				}
			}
		}
		stopChan <- true
	})

	helper.SetEventStreamHeaders(c)
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
		return types.WithOpenAIError(types.OpenAIError{
			Message: "close_response_body_failed",
			Type:    "zai_error",
			Param:   "",
			Code:    "close_response_body_failed",
		}, http.StatusInternalServerError), nil
	}

	completionTokens := service.CountTextToken(strings.Join(respArr, ""), info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	return nil, &usage
}

func ZaiHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	var respArr []string

	// 思考内容处理策略
	transformThinking := func(s string) string {
		// 去除 <summary>…</summary>
		re := regexp.MustCompile(`(?s)<summary>.*?</summary>`)
		s = re.ReplaceAllString(s, "")
		// 清理残留自定义标签
		s = strings.ReplaceAll(s, "</thinking>", "")
		s = strings.ReplaceAll(s, "<Full>", "")
		s = strings.ReplaceAll(s, "</Full>", "")
		s = strings.TrimSpace(s)

		// 根据策略处理 <details> 标签
		switch "strip" { // 对应 THINK_TAGS_MODE
		case "think":
			re := regexp.MustCompile(`<details[^>]*>`)
			s = re.ReplaceAllString(s, "<think>")
			s = strings.ReplaceAll(s, "</details>", "</think>")
		case "strip":
			re := regexp.MustCompile(`<details[^>]*>`)
			s = re.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, "</details>", "")
		}

		// 处理每行前缀 "> "
		s = strings.TrimPrefix(s, "> ")
		s = strings.ReplaceAll(s, "\n> ", "\n")
		return strings.TrimSpace(s)
	}

	for scanner.Scan() {
		info.SetFirstResponseTime()
		data := scanner.Text()
		dataLine := strings.TrimSpace(data)
		common.SysLog(dataLine)

		if strings.HasPrefix(dataLine, "data: ") {
			dataStr := strings.TrimPrefix(dataLine, "data: ")
			if dataStr == "" {
				continue
			}

			// 解析上游SSE数据
			var upstreamData struct {
				Type string `json:"type"`
				Data struct {
					DeltaContent string `json:"delta_content"`
					Phase        string `json:"phase"`
					Done         bool   `json:"done"`
					Usage        struct {
						PromptTokens     int `json:"prompt_tokens"`
						CompletionTokens int `json:"completion_tokens"`
						TotalTokens      int `json:"total_tokens"`
					} `json:"usage,omitempty"`
					Error *struct {
						Detail string `json:"detail"`
						Code   int    `json:"code"`
					} `json:"error,omitempty"`
					Inner *struct {
						Error *struct {
							Detail string `json:"detail"`
							Code   int    `json:"code"`
						} `json:"error,omitempty"`
					} `json:"data,omitempty"`
				} `json:"data"`
				Error *struct {
					Detail string `json:"detail"`
					Code   int    `json:"code"`
				} `json:"error,omitempty"`
			}

			err := json.Unmarshal([]byte(dataStr), &upstreamData)
			if err != nil {
				common.SysLog("SSE数据解析失败: " + err.Error())
				continue
			}

			// 错误检测
			if upstreamData.Error != nil || upstreamData.Data.Error != nil ||
				(upstreamData.Data.Inner != nil && upstreamData.Data.Inner.Error != nil) {
				errObj := upstreamData.Error
				if errObj == nil {
					errObj = upstreamData.Data.Error
				}
				if errObj == nil && upstreamData.Data.Inner != nil {
					errObj = upstreamData.Data.Inner.Error
				}
				common.SysLog(fmt.Sprintf("上游错误: code=%d, detail=%s", errObj.Code, errObj.Detail))
				break
			}

			// 处理内容
			if upstreamData.Data.DeltaContent != "" {
				out := upstreamData.Data.DeltaContent
				if upstreamData.Data.Phase == "thinking" {
					out = transformThinking(out)
				}

				if out != "" {
					respArr = append(respArr, out)
				}
			}

			// 检查是否结束
			if upstreamData.Data.Done || upstreamData.Data.Phase == "done" {
				break
			}
		}
	}

	responseText := strings.Join(respArr, "")
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())

	// 构造完整响应
	content, _ := json.Marshal(responseText)
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
		Created: common.GetTimestamp(),
		Model:   info.UpstreamModelName,
		Choices: []dto.OpenAITextResponseChoice{choice},
	}

	completionTokens := service.CountTextToken(responseText, info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}
	fullTextResponse.Usage = usage

	jsonResponse, err := json.Marshal(fullTextResponse)
	if err != nil {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "marshal_response_body_failed",
			Type:    "zai_error",
			Param:   "",
			Code:    "marshal_response_body_failed",
		}, http.StatusInternalServerError), nil
	}

	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)

	return nil, &usage
}
