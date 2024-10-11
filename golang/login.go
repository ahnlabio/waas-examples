// login.py - WAAS 로그인 API 사용 예제
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"

// 필수 함수 아님. 유틸성 함수
func getBaseURL() string {
	waas_base_url, isExistEnv := os.LookupEnv("WAAS_BASE_URL")
	if !isExistEnv {
		waas_base_url = WAAS_BASE_URL
	}

	return waas_base_url
}

type emailLoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiredIn    int    `json:"expired_in"`
}

func emailLogin(email, encryptedPassword, secureChannelID, auth string) emailLoginResult {
	/*
	   이메일과 암호를 사용하여 로그인 요청을 보냅니다.

	   Args:
	       email (str): 사용자의 이메일 주소.
	       encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
	       secure_channel_id (str): 보안 채널 ID.
	       auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

	   Returns:
	       emailLoginResult: 로그인 요청에 대한 서버의 응답.

	   Raises:
	       HTTPError: 로그인 요청이 실패한 경우.
	*/

	urlStr := fmt.Sprintf("%s/auth/auth-service/v2/login", getBaseURL())
	data := url.Values{
		"grant_type": {"password"},
		"username":   {email},
		"password":   {encryptedPassword},
		"audience":   {"https://mw.myabcwallet.com"},
	}

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal("Failed to create request:", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Secure-Channel", secureChannelID)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status: %d", resp.StatusCode)
	}

	var result emailLoginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("Failed to decode response:", err)
	}

	return result
}

func refreshToken(refreshToken, auth string) emailLoginResult {
	/*
		refresh token 을 사용하여 access token 을 재발급합니다.

		Args:
		    refresh_token (str): refresh token.
		    auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

		Returns:
		    emailLoginResult: 재발급된 access token.
	*/

	urlStr := fmt.Sprintf("%s/auth/auth-service/v2/refresh", getBaseURL())
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal("Failed to create request:", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status: %d", resp.StatusCode)
	}

	var result emailLoginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("Failed to decode response:", err)
	}

	return result
}
