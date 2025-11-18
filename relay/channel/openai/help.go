package openai

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// groq start

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
	var organization, token, memberId, memberSessionId string

	if strings.Contains(key, "#") {
		splitStr := strings.Split(key, "#")
		if len(splitStr) == 4 {
			organization = splitStr[0]
			key = splitStr[1]
			memberId = splitStr[2]
			memberSessionId = splitStr[3]
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
			tokenTemp, err := GerGetSessionToken(key, memberId, memberSessionId)
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
	c.Set("accept-language", "zh-CN,zh;q=0.8")
	c.Set("content-type", "application/json")
	c.Set("origin", "https://chat.groq.com")
	c.Set("referer", "https://chat.groq.com/")
	c.Set("sec-ch-ua", `"Brave";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`)
	c.Set("sec-ch-ua-mobile", "?0")
	c.Set("sec-ch-ua-platform", `"macOS"`)
	c.Set("sec-fetch-dest", "empty")
	c.Set("sec-fetch-mode", "cors")
	c.Set("sec-fetch-site", "cross-site")
	c.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
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

func GerGetSessionToken(apiKey string, memberId string, memberSessionId string) (GerAuthenticateResponse, error) {
	if apiKey == "" {
		return GerAuthenticateResponse{}, errors.New("session token is empty")
	}
	authorization := GerGenerateRefreshToken(apiKey)

	client := http.Client{}
	req, err := http.NewRequest("POST", "https://api.stytchb2b.groq.com/sdk/v1/b2b/sessions/authenticate", strings.NewReader(`{}`))
	if err != nil {
		return GerAuthenticateResponse{}, errors.New("create request failed")
	}
	GerBaseHeader(&req.Header)
	req.Header.Set("Authorization", "Basic "+authorization)

	now := time.Now().UTC()
	formatted := now.Format(time.RFC3339Nano)

	xSdkClient := map[string]interface{}{
		"event_id":                 "event-id-" + uuid.NewString(),
		"app_session_id":           "app-session-id-" + uuid.NewString(),
		"persistent_id":            "persistent-id-" + uuid.NewString(),
		"client_sent_at":           formatted,
		"timezone":                 "Asia/Hong_Kong",
		"stytch_member_id":         memberId,
		"stytch_member_session_id": memberSessionId,
		"app": map[string]string{
			"identifier": "chat.groq.com",
		},
		"sdk": map[string]string{
			"identifier": "Stytch.js Javascript SDK",
			"version":    "5.35.1",
		},
	}
	xSdkClientJson, _ := json.Marshal(xSdkClient)
	common.SysLog(fmt.Sprintf("xSdkClientJson: %s", xSdkClientJson))

	req.Header.Set("X-SDK-Client", base64.StdEncoding.EncodeToString(xSdkClientJson))
	req.Header.Set("X-SDK-Parent-Host", "https://chat.groq.com")

	//for name, values := range req.Header {
	//	for _, value := range values {
	//		common.SysLog(name + ": " + value)
	//	}
	//}

	res, err := client.Do(req)
	if err != nil {
		common.SysLog(err.Error())
		return GerAuthenticateResponse{}, errors.New("request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return GerAuthenticateResponse{}, errors.New("authenticate failed")
	}

	newBodyByte, _ := io.ReadAll(res.Body)
	common.SysLog("body:" + string(newBodyByte))

	var result GerAuthenticateResponse
	err = json.Unmarshal(newBodyByte, &result)
	if err != nil {
		common.SysLog("decoder error:" + err.Error())
		return GerAuthenticateResponse{}, err
	}
	return result, nil
}

func GerGenerateRefreshToken(apiKey string) string {
	prefix := "public-token-live-58df57a9-a1f5-4066-bc0c-2ff942db684f:" + apiKey
	return base64.StdEncoding.EncodeToString([]byte(prefix))
}

// groq end

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

//Zai Start

const (
	ZAI_X_FE_VERSION_DEFAULT = "prod-fe-1.0.125"
	ZAI_BROWSER_UA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
	ZAI_SEC_CH_UA            = "\"Microsoft Edge\";v=\"141\", \"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"141\""
	ZAI_SEC_CH_UA_MOB        = "?0"
	ZAI_SEC_CH_UA_PLAT       = "\"Windows\""
	ZAI_ORIGIN_BASE          = "https://chat.z.ai"
	ZAI_REQUEST_URL          = "https://chat.z.ai"
)

type ZaiUpstreamRequest struct {
	Stream          bool                     `json:"stream"`
	Model           string                   `json:"model"`
	Messages        []map[string]interface{} `json:"messages"`
	Params          map[string]interface{}   `json:"params"`
	Features        map[string]interface{}   `json:"features"`
	BackgroundTasks map[string]bool          `json:"background_tasks,omitempty"`
	ChatID          string                   `json:"chat_id,omitempty"`
	ID              string                   `json:"id,omitempty"`
	MCPServers      []string                 `json:"mcp_servers,omitempty"`
	ModelItem       struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		OwnedBy string `json:"owned_by"`
	} `json:"model_item,omitempty"`
	ToolServers     []string          `json:"tool_servers,omitempty"`
	Variables       map[string]string `json:"variables,omitempty"`
	Tool            interface{}       `json:"tool,omitempty"`
	SignaturePrompt string            `json:"signature_prompt,omitempty"`
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

var SUPPORTED_Z_MODELS = []ModelZaiConfig{
	{
		ID:         "glm-4.6-api-v1",
		Name:       "GLM-4.6",
		UpstreamID: "GLM-4-6-API-V1",
		Capabilities: ModelZaiCapabilities{
			Vision:   false,
			MCP:      true,
			Thinking: true,
		},
		DefaultParams: map[string]interface{}{
			"max_tokens": 195000,
		},
	},
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
			"max_tokens": 128000,
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

type zaiAuthResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

func getZaiFeVersion() string {
	cacheKey := "zaiFeVersion"
	if common.RedisEnabled {
		if cached, err := common.RedisGet(cacheKey); err == nil && cached != "" {
			return cached
		}
	} else {
		if cached, found := helpCache.HelpCacheGet(cacheKey); found {
			return cached.(string)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", ZAI_REQUEST_URL, nil)
	if err != nil {
		return ZAI_X_FE_VERSION_DEFAULT
	}
	req.Header.Set("User-Agent", ZAI_BROWSER_UA)

	resp, err := client.Do(req)
	if err != nil {
		return ZAI_X_FE_VERSION_DEFAULT
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ZAI_X_FE_VERSION_DEFAULT
	}

	re := regexp.MustCompile(`prod-fe-[\d.]+`)
	if match := re.Find(body); match != nil {
		version := string(match)
		if common.RedisEnabled {
			_ = common.RedisSet(cacheKey, version, 24*time.Hour)
		} else {
			helpCache.HelpCacheSet(cacheKey, version, 24*60*60)
		}
		return version
	}

	return ZAI_X_FE_VERSION_DEFAULT
}

func fetchZaiAuth(token string, channelBaseUrl string) (*zaiAuthResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var currentUrl string
	if channelBaseUrl != "" {
		currentUrl = channelBaseUrl
	} else {
		currentUrl = ZAI_REQUEST_URL
	}
	req, err := http.NewRequest("GET", currentUrl+"/api/v1/auths/", nil)
	if err != nil {
		return nil, err
	}
	if common.DebugEnabled {
		common.SysLog("fetchZaiAuth: " + token)
	}
	// 伪装浏览器头
	req.Header.Set("User-Agent", ZAI_BROWSER_UA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("X-FE-Version", getZaiFeVersion())
	req.Header.Set("sec-ch-ua", ZAI_SEC_CH_UA)
	req.Header.Set("sec-ch-ua-mobile", ZAI_SEC_CH_UA_MOB)
	req.Header.Set("sec-ch-ua-platform", ZAI_SEC_CH_UA_PLAT)
	req.Header.Set("Origin", ZAI_ORIGIN_BASE)
	req.Header.Set("Referer", ZAI_ORIGIN_BASE+"/")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zai auth status=%d", resp.StatusCode)
	}
	var body zaiAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Token == "" {
		body.Token = token
	}
	return &body, nil
}

func ensureZaiAuth(info *relaycommon.RelayInfo) (*zaiAuthResponse, error) {
	//authData, found := helpCache.HelpCacheGet(fmt.Sprintf("zaiAuth:%v", info.ChannelId))
	//var key string
	//if found {
	//	key = authData.(*zaiAuthResponse).Token
	//} else {
	//	key = strings.TrimSpace(info.ApiKey)
	//}
	key := strings.TrimSpace(info.ApiKey)

	var auth *zaiAuthResponse
	var err error
	if key == "" || key == "zai" {
		auth, err = fetchZaiAuth("", info.ChannelBaseUrl)
		if err != nil {
			return nil, err
		}
	} else {
		auth, err = fetchZaiAuth(key, info.ChannelBaseUrl)
		if err != nil {
			// 如果获取用户信息失败，返回原始 token，避免请求直接失败
			common.SysError("fetchZaiAuth failed: " + err.Error())
			return &zaiAuthResponse{ID: "", Token: key}, nil
		}
	}
	if auth.Token != "" {
		info.ApiKey = auth.Token
		//缓存3分钟
		//helpCache.HelpCacheSet(fmt.Sprintf("zaiAuth:%v", info.ChannelId), auth, 3*60*60)
	}
	return auth, nil
}

func zs(e, t, s string) (string, string, error) {
	// 1. const r = Number(s)
	r, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse timestamp s: %w", err)
	}

	// 2. const i = s
	i := s

	// 3. const a = n.encode(t) -> const w = btoa(String.fromCharCode(...a))
	// Go 中可以直接对 t 的字节切片进行 Base64 编码
	a := []byte(t)
	w := base64.StdEncoding.EncodeToString(a)

	// 4. const c = `${e}|${w}|${i}`
	c := fmt.Sprintf("%s|%s|%s", e, w, i)

	// 5. const E = Math.floor(r / (5 * 60 * 1e3))
	E := r / (5 * 60 * 1000)

	// 6. const A = Te.sha256.hmac("junjie", `${E}`)
	// 第一次 HMAC-SHA256
	key1 := []byte("key-@@@@)))()((9))-xxxx&&&%%%%%")
	message1 := []byte(strconv.FormatInt(E, 10))

	h1 := hmac.New(sha256.New, key1)
	h1.Write(message1)
	A := h1.Sum(nil) // A 是一个字节切片 ([]byte)

	// 7. const k = Te.sha256.hmac(A, c).toString();
	// 第二次 HMAC-SHA256
	// 【关键修复点】: JS 的 Te 库可能将密钥 A 转换为十六进制字符串后再使用
	// 因此，我们在这里模拟这个行为
	key2 := []byte(hex.EncodeToString(A)) // 将 A 转换为十六进制字符串，再作为密钥
	message2 := []byte(c)

	h2 := hmac.New(sha256.New, key2)
	h2.Write(message2)
	hashBytes := h2.Sum(nil)

	// 将哈希结果转换为十六进制字符串
	k := hex.EncodeToString(hashBytes)

	// 8. 返回结果
	return k, i, nil
}

func generateZaiSignature(params map[string]string, content string) (string, string, error) {
	required := []string{"timestamp", "requestId", "user_id"}
	for _, key := range required {
		if strings.TrimSpace(params[key]) == "" {
			return "", "", fmt.Errorf("missing param: %s", key)
		}
	}

	signatureTime := time.Now().UnixMilli()
	signatureExpire := signatureTime / (5 * 60 * 1000)
	signature1Plain := fmt.Sprintf("%d", signatureExpire)
	signature1 := hmacSHA256Hex([]byte("junjie"), signature1Plain)

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		parts = append(parts, k)
		parts = append(parts, params[k])
	}
	signatureParams := strings.Join(parts, ",")
	signaturePlain := fmt.Sprintf("%s|%s|%d", signatureParams, content, signatureTime)
	signature := hmacSHA256Hex([]byte(signature1), signaturePlain)

	return signature, fmt.Sprintf("%d", signatureTime), nil
}

func hmacSHA256Hex(key []byte, message string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func getZaiUpstreamModel(modelID string) *ModelZaiConfig {
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
		"glm-4.6":              "GLM-4-6-API-V1",
		"glm4.6":               "GLM-4-6-API-V1",
		"glm_4.6":              "GLM-4-6-API-V1",
		"glm-4.6-api-v1":       "GLM-4-6-API-V1",
	}

	var model string
	if mapped, exists := modelMappings[normalized]; exists {
		model = mapped
	} else {
		model = "GLM-4-6-API-V1"
	}

	for _, modelConfig := range SUPPORTED_Z_MODELS {
		if modelConfig.UpstreamID == model {
			return &modelConfig
		}
	}

	return &SUPPORTED_Z_MODELS[0]
}

func GenZaiBody(requestBody io.Reader, info *relaycommon.RelayInfo) io.Reader {
	bodyBytes, _ := io.ReadAll(requestBody)

	var requestMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &requestMap); err != nil {
		return bytes.NewReader(bodyBytes)
	}

	chatID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
	msgID := fmt.Sprintf("%d", time.Now().UnixNano())

	authInfo, err := ensureZaiAuth(info)
	if err != nil {
		common.SysError("ensureZaiAuth error: " + err.Error())
		return bytes.NewReader(bodyBytes)
	}

	lastMessageContent := ""

	// 决定是否启用思考功能
	enableThinking := false
	if thinkingVal, ok := requestMap["thinking"]; ok {
		if thinkingBool, ok := thinkingVal.(bool); ok {
			enableThinking = thinkingBool
		} else if thinkingMap, ok := thinkingVal.(map[string]interface{}); ok {
			if thinkingType, exists := thinkingMap["type"]; exists {
				if typeStr, ok := thinkingType.(string); ok {
					if typeStr == "disabled" {
						enableThinking = false
					} else if typeStr == "enabled" {
						enableThinking = true
					}
				}
			}
		}
	}
	if reasoningVal, ok := requestMap["reasoning"]; ok {
		if reasoningBool, ok := reasoningVal.(bool); ok && reasoningBool {
			enableThinking = true
		}
	}
	// 如果请求带有 reasoning_effort 参数且有值，也启用思考
	if reasoningEffortVal, ok := requestMap["reasoning_effort"]; ok {
		if effortStr, ok := reasoningEffortVal.(string); ok && effortStr != "" {
			enableThinking = true
		}
	}
	common.SysLog(fmt.Sprintf("enableThinking: %v", enableThinking))

	modelConfig := &SUPPORTED_Z_MODELS[0]
	if modelVal, ok := requestMap["model"]; ok {
		if modelStr, ok := modelVal.(string); ok {
			modelConfig = getZaiUpstreamModel(modelStr)
		}
	}

	// 处理消息数组，参考zai.js的transformRequestIn逻辑
	var messages []map[string]interface{}
	if origMessages, ok := requestMap["messages"]; ok {
		if messagesArray, ok := origMessages.([]interface{}); ok {
			for _, origMsg := range messagesArray {
				if msgMap, ok := origMsg.(map[string]interface{}); ok {
					msg := make(map[string]interface{})

					if content, exists := msgMap["content"]; exists {
						switch typed := content.(type) {
						case string:
							lastMessageContent = typed
						case []interface{}:
							for _, part := range typed {
								if partMap, ok := part.(map[string]interface{}); ok {
									if partType, ok := partMap["type"].(string); ok && partType == "text" {
										if textStr, ok := partMap["text"].(string); ok {
											lastMessageContent = textStr
											break
										}
									}
								}
							}
						}
					}

					// 处理content，支持数组和字符串格式
					if content, exists := msgMap["content"]; exists {
						if contentArray, ok := content.([]interface{}); ok {
							// content是数组格式
							newContent := []interface{}{}
							for _, part := range contentArray {
								if partMap, ok := part.(map[string]interface{}); ok {
									newPart := make(map[string]interface{})

									// 处理type字段
									if partType, exists := partMap["type"]; exists {
										newPart["type"] = partType
									}

									// 处理text字段
									if text, exists := partMap["text"]; exists {
										newPart["text"] = text
									}

									// 处理image_url字段
									if imageUrl, exists := partMap["image_url"]; exists {
										if imageUrlMap, ok := imageUrl.(map[string]interface{}); ok {
											if url, urlExists := imageUrlMap["url"]; urlExists {
												if urlStr, ok := url.(string); ok && !strings.HasPrefix(urlStr, "http") {
													// 保留原有的图片处理逻辑
													newPart["image_url"] = imageUrl
												} else {
													newPart["image_url"] = imageUrl
												}
											}
										}
									}

									// 忽略cache_control等其他字段，只保留核心字段
									newContent = append(newContent, newPart)
								}
							}

							// 如果是system角色，参考zai.js转换为user角色并添加前缀
							if role, ok := msg["role"].(string); ok && role == "system" {
								msg["role"] = "user"
								// 在content数组开头添加前缀
								prefixPart := map[string]interface{}{
									"type": "text",
									"text": "This is a system command, you must enforce compliance.",
								}
								newContent = append([]interface{}{prefixPart}, newContent...)
							}

							msg["content"] = newContent
						} else if contentStr, ok := content.(string); ok {
							// content是字符串格式
							if role, ok := msg["role"].(string); ok && role == "system" {
								msg["role"] = "user"
								msg["content"] = "This is a system command, you must enforce compliance." + contentStr
							} else {
								msg["content"] = contentStr
							}
						}
					}

					// 复制role
					if role, exists := msgMap["role"]; exists {
						if roleStr, ok := role.(string); ok {
							if roleStr == "tool" {
								msg["role"] = "user"
							}
							if roleStr == "developer" {
								msg["role"] = "system"
							}
						} else {
							msg["role"] = role
						}
						msg["role"] = role
					}

					messages = append(messages, msg)
				}
			}
		}
	}

	// 处理tools参数
	var tools interface{}
	if toolsVal, exists := requestMap["tools"]; exists && !enableThinking {
		if toolsArray, ok := toolsVal.([]interface{}); ok && len(toolsArray) > 0 {
			tools = toolsArray
		}
	}

	if tools != nil {
		toolMsg := map[string]interface{}{
			"role": "user",
			"content": "\n\n如果需要调用工具，请仅用以下结构体回复（确保标签完整闭合）:\n" +
				"▶{\n" +
				"  \"tool_calls\": [\n" +
				"    {\n" +
				"      \"id\": \"call_xxx\",\n" +
				"      \"type\": \"function\",\n" +
				"      \"function\": {\n" +
				"        \"name\": \"function_name\",\n" +
				"        \"arguments\": \"{\\\"param1\\\": \\\"value1\\\"}\"\n" +
				"      }\n" +
				"    }\n" +
				"  ]\n" +
				"}◀",
		}
		if toolsArray, ok := tools.([]interface{}); ok {
			lines := make([]string, 0, len(toolsArray))
			for _, tool := range toolsArray {
				toolMap, ok := tool.(map[string]interface{})
				if !ok {
					continue
				}
				if toolType, ok := toolMap["type"].(string); !ok || toolType != "function" {
					continue
				}
				functionDef, _ := toolMap["function"].(map[string]interface{})
				name, _ := functionDef["name"].(string)
				if name == "" {
					name = "unknown"
				}
				desc, _ := functionDef["description"].(string)
				params, _ := functionDef["parameters"].(map[string]interface{})

				toolDesc := []string{fmt.Sprintf("- %s: %s", name, desc)}

				requiredSet := map[string]struct{}{}
				if params != nil {
					if reqList, exists := params["required"]; exists {
						switch reqVal := reqList.(type) {
						case []interface{}:
							for _, item := range reqVal {
								if str, ok := item.(string); ok {
									requiredSet[str] = struct{}{}
								}
							}
						case []string:
							for _, str := range reqVal {
								requiredSet[str] = struct{}{}
							}
						}
					}
				}

				var properties map[string]interface{}
				if params != nil {
					if props, ok := params["properties"].(map[string]interface{}); ok {
						properties = props
					}
				}

				for pname, pinfo := range properties {
					infoMap, _ := pinfo.(map[string]interface{})
					pType := "any"
					if t, ok := infoMap["type"].(string); ok && t != "" {
						pType = t
					}
					pDesc := ""
					if d, ok := infoMap["description"].(string); ok {
						pDesc = d
					}
					reqText := " (optional)"
					if _, ok := requiredSet[pname]; ok {
						reqText = " (required)"
					}
					toolDesc = append(toolDesc, fmt.Sprintf("  - %s (%s)%s: %s", pname, pType, reqText, pDesc))
				}
				lines = append(lines, strings.Join(toolDesc, "\n"))
			}

			if len(lines) > 0 {
				if content, ok := toolMsg["content"].(string); ok {
					toolMsg["content"] = "\n\n可用的工具函数:\n\n" + strings.Join(lines, "\n") + content
				}
			}
		}
		messages = append([]map[string]interface{}{toolMsg}, messages...)
	}

	// 构造上游请求
	upstreamReq := ZaiUpstreamRequest{
		Stream:   true, // 总是使用流式从上游获取
		ChatID:   chatID,
		ID:       msgID,
		Model:    modelConfig.UpstreamID, // 根据模型名称获取上游实际模型ID
		Messages: messages,
		Params:   map[string]interface{}{},
		Features: map[string]interface{}{
			"enable_thinking": enableThinking,
		},
		BackgroundTasks: map[string]bool{
			"title_generation": false,
			"tags_generation":  false,
		},
		MCPServers: []string{},
		ModelItem: struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			OwnedBy string `json:"owned_by"`
		}{ID: modelConfig.UpstreamID, Name: modelConfig.Name, OwnedBy: "openai"},
		ToolServers: []string{},
		Variables: map[string]string{
			"{{USER_NAME}}":        "User",
			"{{USER_LOCATION}}":    "Unknown",
			"{{CURRENT_DATETIME}}": time.Now().Format("2006-01-02 15:04:05"),
		},
		SignaturePrompt: lastMessageContent,
	}

	//if tools != nil {
	//	upstreamReq.Tool = tools
	//}

	reqBody, err := json.Marshal(upstreamReq)
	if err != nil {
		return bytes.NewReader(bodyBytes)
	}
	if common.DebugEnabled {
		common.SysLog("GenZaiBody: " + string(reqBody))
	}

	timestamp := time.Now().UnixMilli()
	timestampStr := fmt.Sprintf("%d", timestamp)
	requestID := uuid.NewString()
	params := url.Values{}
	params.Set("timestamp", timestampStr)
	params.Set("requestId", requestID)
	var signature string
	if authInfo != nil && authInfo.ID != "" {
		params.Set("user_id", authInfo.ID)
		sig, sigTs, sigErr := zs(fmt.Sprintf("requestId,%s,timestamp,%s,user_id,%s", requestID, timestampStr, authInfo.ID), lastMessageContent, timestampStr)
		//sig, sigTs, sigErr := generateZaiSignature(map[string]string{
		//	"requestId": requestID,
		//	"timestamp": timestampStr,
		//	"user_id":   authInfo.ID,
		//}, lastMessageContent)
		//if sigErr != nil {
		//	common.SysError("generateZaiSignature failed: " + sigErr.Error())
		//} else {
		//	signature = sig
		//	params.Set("signature_timestamp", sigTs)
		//}
		if sigErr != nil {
			common.SysError("zs failed: " + sigErr.Error())
		} else {
			signature = sig
			params.Set("signature_timestamp", sigTs)
		}
	}

	var currentUrl string
	if info.ChannelBaseUrl != "" {
		currentUrl = info.ChannelBaseUrl
	} else {
		currentUrl = ZAI_REQUEST_URL
	}
	baseURL := currentUrl + "/api/v2/chat/completions"
	fullURL := baseURL
	if query := params.Encode(); query != "" {
		fullURL = baseURL + "?" + query
	}

	headerOverride := map[string]interface{}{
		"Content-Type":       "application/json",
		"Accept":             "*/*",
		"Accept-Language":    "zh-CN,zh;q=0.9",
		"Cache-Control":      "no-cache",
		"Pragma":             "no-cache",
		"Connection":         "keep-alive",
		"User-Agent":         ZAI_BROWSER_UA,
		"Authorization":      "Bearer " + info.ApiKey,
		"sec-ch-ua":          ZAI_SEC_CH_UA,
		"sec-ch-ua-mobile":   ZAI_SEC_CH_UA_MOB,
		"sec-ch-ua-platform": ZAI_SEC_CH_UA_PLAT,
		"X-FE-Version":       getZaiFeVersion(),
		"Origin":             ZAI_ORIGIN_BASE,
		"Referer":            ZAI_ORIGIN_BASE + "/c/" + chatID,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"full_url":           fullURL,
	}
	if signature != "" {
		headerOverride["X-Signature"] = signature
	}
	info.HeadersOverride = headerOverride

	return bytes.NewReader(reqBody)
}

func GenZaiHeader(c *http.Header, info *relaycommon.RelayInfo) {
	keepKey := []string{"Content-Type", "Accept", "Accept-Language", "Cache-Control", "Pragma", "User-Agent", "Authorization", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "X-FE-Version", "X-Signature", "Origin", "Referer", "Connection", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site"}
	canonical := make(map[string]struct{}, len(keepKey))
	for _, k := range keepKey {
		canonical[http.CanonicalHeaderKey(k)] = struct{}{}
	}
	h := *c
	for k := range h {
		if _, ok := canonical[http.CanonicalHeaderKey(k)]; !ok {
			c.Del(k)
		}
	}
}

// 处理响应数据的上下文结构
type zaiResponseContext struct {
	allContent      strings.Builder
	thinkingContent strings.Builder
	toolCallContent strings.Builder
	currentUsage    *dto.Usage
	hasToolCall     bool
	endToolCall     bool
	hasThinking     bool
	endThinking     bool
	toolCalls       []dto.ToolCallResponse
	endRequest      bool
}

type zaiCompletion struct {
	Done    bool `json:"done"`
	Choices []struct {
		Message struct {
			Content          *string       `json:"content"`
			ToolCalls        []zaiToolCall `json:"tool_calls"`
			ReasoningContent *string       `json:"reasoning_content"`
		} `json:"message"`
	} `json:"choices"`
}

type zaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
	Index int `json:"index"`
}

// 创建流式响应的辅助函数
func createStreamResponse(id string, created int64, model string, content string, role string, isFinish bool, reason string) *dto.ChatCompletionsStreamResponse {
	choice := dto.ChatCompletionsStreamResponseChoice{
		Index: 0,
		Delta: dto.ChatCompletionsStreamResponseChoiceDelta{},
	}
	if role != "" {
		choice.Delta.Role = role
	}

	if content != "" {
		choice.Delta.SetContentString(content)
	}

	if isFinish {
		if reason != "" {
			choice.FinishReason = &reason
		} else {
			finishReason := "stop"
			choice.FinishReason = &finishReason
		}
	}

	return &dto.ChatCompletionsStreamResponse{
		Id:      id,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []dto.ChatCompletionsStreamResponseChoice{choice},
	}
}

// ZaiStreamMessage represents the top-level JSON object in each log line.
type ZaiStreamMessage struct {
	Type string        `json:"type"`
	Data ZaiStreamData `json:"data"`
}

// ZaiStreamData contains the actual content and metadata.
type ZaiStreamData struct {
	DeltaContent string `json:"delta_content"`
	EditContent  string `json:"edit_content,omitempty"`
	Phase        string `json:"phase"`
	Done         bool   `json:"done"`
}

type ZaiSourceToolCallWrapper struct {
	ToolCalls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

// 转换思考内容的通用函数
func transformZaiThinkingContent(s string) string {
	// 去除 <summary>…</summary>
	s = regexp.MustCompile(`(?s)<summary>.*?</summary>`).ReplaceAllString(s, "")
	// 清理残留自定义标签，如 </thinking>、<Full> 等
	s = strings.ReplaceAll(s, "</thinking>", "")
	s = strings.ReplaceAll(s, "<Full>", "")
	s = strings.ReplaceAll(s, "</Full>", "")
	s = strings.TrimSpace(s)

	s = regexp.MustCompile(`<details[^>]*>`).ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "</details>", "")

	// 处理每行前缀 "> "（包括起始位置）
	s = strings.TrimPrefix(s, "> ")
	s = strings.ReplaceAll(s, "\n> ", "\n")
	return strings.TrimSpace(s)
}

func ZaiStreamHandler(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (*types.NewAPIError, *dto.Usage) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	dataChan := make(chan string)
	stopChan := make(chan bool)

	allZai := &zaiResponseContext{}
	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	createdTime := common.GetTimestamp()
	startDelimiter := "▶"
	endDelimiter := "◀"

	gopool.Go(func() {
		defer func() {
			stopChan <- true
		}()

		firstDeltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "", "assistant", false, "")
		firstDataBytes, _ := json.Marshal(firstDeltaResp)
		dataChan <- string(firstDataBytes)

		for scanner.Scan() {
			info.SetFirstResponseTime()
			line := strings.TrimSpace(scanner.Text())
			if common.DebugEnabled {
				common.SysLog(fmt.Sprintf("[ZaiStreamHandler] %s", line))
			}
			if strings.HasPrefix(line, "data:") {
				chunkStr := strings.TrimSpace(line[5:])
				if chunkStr == "" {
					continue
				}

				var msg ZaiStreamMessage
				if err := json.Unmarshal([]byte(chunkStr), &msg); err != nil {
					log.Printf("Error unmarshalling source JSON: %v", err)
					continue
				}
				switch msg.Data.Phase {
				case "thinking":
					// 将所有 thinking 内容写入缓冲区，暂时不发送
					cleaned := transformZaiThinkingContent(msg.Data.DeltaContent)
					allZai.thinkingContent.WriteString(cleaned)

					// 为兼容性保留 <think> 标签包裹的内容
					contentWithTag := cleaned
					if !allZai.hasThinking {
						contentWithTag = "<think>" + cleaned
						allZai.endThinking = false
					}
					allZai.hasThinking = true

					// 创建流式响应，content 包含 <think> 标签（兼容现有程序）
					deltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, contentWithTag, "", false, "")

					// 注释掉 reasoning_content 字段，避免客户端报错 "reasoning part reasoning-0 not found"
					// 某些客户端要求 reasoning_content 必须配套 reasoning_parts 结构
					// 当前通过 <think> 标签的方式已经能满足大多数客户端的需求
					//if len(deltaResp.Choices) > 0 {
					//	deltaResp.Choices[0].Delta.ReasoningContent = &cleaned
					//}

					dataBytes, _ := json.Marshal(deltaResp)
					dataChan <- string(dataBytes)
				case "answer", "other":
					if allZai.hasThinking && !allZai.endThinking {
						allZai.endThinking = true
						deltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "</think>", "", false, "")
						dataBytes, _ := json.Marshal(deltaResp)
						dataChan <- string(dataBytes)
					}
					var currentAnswerContent string
					if msg.Data.EditContent != "" {
						separator := "</details>"
						if parts := strings.SplitN(msg.Data.EditContent, separator, 2); len(parts) == 2 {
							// The part after </details> is the first piece of the answer
							currentAnswerContent = strings.TrimSpace(parts[1])
						} else {
							currentAnswerContent = msg.Data.EditContent
						}
					} else {
						// This is a normal answer chunk
						currentAnswerContent = msg.Data.DeltaContent
					}

					if strings.Contains(currentAnswerContent, startDelimiter) || strings.Contains(currentAnswerContent, endDelimiter) || (allZai.hasToolCall && !allZai.endToolCall) {
						if strings.Contains(currentAnswerContent, startDelimiter) {
							allZai.hasToolCall = true
							allZai.endToolCall = false
							if parts := strings.SplitN(currentAnswerContent, startDelimiter, 2); len(parts) == 2 {
								currentAnswerContent = parts[0]
								allZai.toolCallContent.WriteString(parts[1])
							}
						} else if strings.Contains(currentAnswerContent, endDelimiter) {
							allZai.endToolCall = true
							if parts := strings.SplitN(currentAnswerContent, endDelimiter, 2); len(parts) == 2 {
								currentAnswerContent = parts[1]
								allZai.toolCallContent.WriteString(parts[0])
							}
						} else if allZai.hasToolCall && !allZai.endToolCall {
							allZai.toolCallContent.WriteString(currentAnswerContent)
							continue
						}
					}

					if currentAnswerContent != "" {
						allZai.allContent.WriteString(currentAnswerContent)
						deltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, currentAnswerContent, "", false, "")
						dataBytes, _ := json.Marshal(deltaResp)
						dataChan <- string(dataBytes)
					}
				case "done":
					if allZai.hasThinking && !allZai.endThinking {
						allZai.endThinking = true
						deltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "</think>", "", false, "")
						dataBytes, _ := json.Marshal(deltaResp)
						dataChan <- string(dataBytes)
					}
					if allZai.hasToolCall && !allZai.endToolCall {
						allZai.endToolCall = true
					}

					stopChan <- true
					return
				}
			}
		}
	})

	helper.SetEventStreamHeaders(c)
	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-dataChan:
			if common.DebugEnabled {
				common.SysLog(fmt.Sprintf("[ZaiStreamResponseHandler] %s", data))
			}
			c.Render(-1, common.CustomEvent{Data: "data: " + data})
			return true
		case <-stopChan:
			if allZai.hasToolCall && allZai.toolCallContent.String() != "" {
				fullToolCallJSON := allZai.toolCallContent.String()
				var wrapper ZaiSourceToolCallWrapper
				if err := json.Unmarshal([]byte(fullToolCallJSON), &wrapper); err != nil {
					common.SysError(fmt.Sprintf("failed to unmarshal tool call json: %s", fullToolCallJSON))
				} else {
					for i, tc := range wrapper.ToolCalls {
						currentTool := dto.ToolCallResponse{
							Index: &i,
							ID:    tc.ID,
							Type:  tc.Type,
							Function: dto.FunctionResponse{
								Name:      tc.Function.Name,
								Arguments: tc.Function.Arguments,
							},
						}
						allZai.toolCalls = append(allZai.toolCalls, currentTool)
					}
					choice := dto.ChatCompletionsStreamResponseChoice{
						Index: 0,
						Delta: dto.ChatCompletionsStreamResponseChoiceDelta{
							ToolCalls: allZai.toolCalls,
						},
					}
					deltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "", "", false, "")
					deltaResp.Choices = []dto.ChatCompletionsStreamResponseChoice{choice}
					dataBytes, _ := json.Marshal(deltaResp)
					if common.DebugEnabled {
						common.SysLog(fmt.Sprintf("[ZaiStreamResponseHandler] %s", string(dataBytes)))
					}
					c.Render(-1, common.CustomEvent{Data: "data: " + string(dataBytes)})

					endDeltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "", "", true, "tool_calls")
					endDataBytes, _ := json.Marshal(endDeltaResp)
					if common.DebugEnabled {
						common.SysLog(fmt.Sprintf("[ZaiStreamResponseHandler] %s", string(endDataBytes)))
					}
					c.Render(-1, common.CustomEvent{Data: "data: " + string(endDataBytes)})
				}
			} else {
				endDeltaResp := createStreamResponse(responseId, createdTime, info.UpstreamModelName, "", "", true, "stop")
				endDataBytes, _ := json.Marshal(endDeltaResp)
				if common.DebugEnabled {
					common.SysLog(fmt.Sprintf("[ZaiStreamResponseHandler] %s", string(endDataBytes)))
				}
				c.Render(-1, common.CustomEvent{Data: "data: " + string(endDataBytes)})
			}
			if common.DebugEnabled {
				common.SysLog(fmt.Sprintf("[ZaiStreamResponseHandler] %s", "[DONE]"))
			}
			c.Render(-1, common.CustomEvent{Data: "data: [DONE]"})

			return false
		}
	})

	err := resp.Body.Close()
	if err != nil {
		return createCloseBodyError()
	}

	completionTokens := service.CountTextToken(allZai.allContent.String(), info.UpstreamModelName)
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

	allZai := &zaiResponseContext{}
	startDelimiter := "▶"
	endDelimiter := "◀"

	for scanner.Scan() {
		info.SetFirstResponseTime()
		line := strings.TrimSpace(scanner.Text())
		if common.DebugEnabled {
			common.SysLog(fmt.Sprintf("[ZaiHandler] %s", line))
		}
		if strings.HasPrefix(line, "data:") {
			chunkStr := strings.TrimSpace(line[5:])
			if chunkStr == "" {
				continue
			}

			var msg ZaiStreamMessage
			if err := json.Unmarshal([]byte(chunkStr), &msg); err != nil {
				log.Printf("Error unmarshalling source JSON: %v", err)
				continue
			}
			switch msg.Data.Phase {
			case "thinking":
				// 将所有 thinking 内容写入缓冲区，暂时不发送
				cleaned := transformZaiThinkingContent(msg.Data.DeltaContent)
				allZai.thinkingContent.WriteString(cleaned)
				allZai.hasThinking = true
			case "answer", "other":
				var currentAnswerContent string
				if msg.Data.EditContent != "" {
					separator := "</details>"
					if parts := strings.SplitN(msg.Data.EditContent, separator, 2); len(parts) == 2 {
						// The part after </details> is the first piece of the answer
						currentAnswerContent = strings.TrimSpace(parts[1])
					} else {
						currentAnswerContent = msg.Data.EditContent
					}
				} else {
					// This is a normal answer chunk
					currentAnswerContent = msg.Data.DeltaContent
				}

				if strings.Contains(currentAnswerContent, startDelimiter) || strings.Contains(currentAnswerContent, endDelimiter) || (allZai.hasToolCall && !allZai.endToolCall) {
					if strings.Contains(currentAnswerContent, startDelimiter) {
						allZai.hasToolCall = true
						allZai.endToolCall = false
						if parts := strings.SplitN(currentAnswerContent, startDelimiter, 2); len(parts) == 2 {
							currentAnswerContent = parts[0]
							allZai.toolCallContent.WriteString(parts[1])
						}
					} else if strings.Contains(currentAnswerContent, endDelimiter) {
						allZai.endToolCall = true
						if parts := strings.SplitN(currentAnswerContent, endDelimiter, 2); len(parts) == 2 {
							currentAnswerContent = parts[1]
							allZai.toolCallContent.WriteString(parts[0])
						}
					} else if allZai.hasToolCall && !allZai.endToolCall {
						allZai.toolCallContent.WriteString(currentAnswerContent)
						continue
					}
				}

				if currentAnswerContent != "" {
					allZai.allContent.WriteString(currentAnswerContent)
				}
			case "done":
				if allZai.hasThinking && !allZai.endThinking {
					allZai.endThinking = true
				}
				if allZai.hasToolCall && !allZai.endToolCall {
					allZai.endToolCall = true
				}

				break
			}
		}
	}

	err := resp.Body.Close()
	if err != nil {
		return createCloseBodyError()
	}

	if allZai.hasToolCall && allZai.toolCallContent.String() != "" {
		fullToolCallJSON := allZai.toolCallContent.String()
		var wrapper ZaiSourceToolCallWrapper
		if err := json.Unmarshal([]byte(fullToolCallJSON), &wrapper); err != nil {
			common.SysError(fmt.Sprintf("failed to unmarshal tool call json: %s", fullToolCallJSON))
		} else {
			for i, tc := range wrapper.ToolCalls {
				currentTool := dto.ToolCallResponse{
					Index: &i,
					ID:    tc.ID,
					Type:  tc.Type,
					Function: dto.FunctionResponse{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				}
				allZai.toolCalls = append(allZai.toolCalls, currentTool)
			}
		}
	}

	if allZai.allContent.Len() == 0 && len(allZai.toolCalls) == 0 {
		return types.WithOpenAIError(types.OpenAIError{
			Message: "empty_response_content",
			Type:    "zai_error",
			Param:   "",
			Code:    "empty_response_content",
		}, http.StatusInternalServerError), nil
	}

	responseId := fmt.Sprintf("chatcmpl-%s", common.GetUUID())
	createdTime := common.GetTimestamp()

	// 构建响应消息
	message := dto.Message{
		Role:    "assistant",
		Content: allZai.allContent.String(),
	}
	// 添加thinking内容（如果有）
	if allZai.hasThinking && allZai.thinkingContent.Len() > 0 {
		message.Thinking = &dto.ThinkingContent{
			Content:   allZai.thinkingContent.String(),
			Signature: fmt.Sprintf("%d", time.Now().Unix()),
		}
		message.ReasoningContent = allZai.thinkingContent.String()
	}

	// 添加tool_calls（如果有）
	if len(allZai.toolCalls) > 0 {
		toolCallsJson, _ := json.Marshal(allZai.toolCalls)
		message.ToolCalls = toolCallsJson
	}

	choice := dto.OpenAITextResponseChoice{
		Index:   0,
		Message: message,
	}

	if allZai.hasToolCall {
		choice.FinishReason = "tool_calls"
	} else {
		choice.FinishReason = "stop"
	}

	completionTokens := service.CountTextToken(allZai.allContent.String(), info.UpstreamModelName)
	usage := dto.Usage{
		PromptTokens:     info.PromptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      info.PromptTokens + completionTokens,
	}

	fullTextResponse := dto.OpenAITextResponse{
		Id:      responseId,
		Object:  "chat.completion",
		Created: createdTime,
		Model:   info.UpstreamModelName,
		Choices: []dto.OpenAITextResponseChoice{choice},
		Usage:   usage,
	}

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

// 创建关闭响应错误的辅助函数
func createCloseBodyError() (*types.NewAPIError, *dto.Usage) {
	return types.WithOpenAIError(types.OpenAIError{
		Message: "close_response_body_failed",
		Type:    "zai_error",
		Param:   "",
		Code:    "close_response_body_failed",
	}, http.StatusInternalServerError), nil
}

//Zai End
