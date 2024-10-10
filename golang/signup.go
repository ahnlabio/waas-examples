package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
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

func isExistUser(email string) bool {
	/*
	   주어진 사용자 이메일이 이미 가입된 사용자 인지 확인합니다.

	   Args:
	       email (str): 확인할 사용자의 이메일 주소.

	   Returns:
	       bool: 이미 존재하는 계정인 경우 True, 가입되지 않은 계정인 경우 False.

	   Raises:
	       HTTPError: 요청이 실패한 경우.

	   Note:
	       이미 가입된 이메일인 경우, 서버는 상태 코드 400과 함께 다음과 같은 응답을 반환합니다:
	       {
	           "code": 606,
	           "msg": "Email is already in use.",
	           "object": null,
	           "errorResponse": "{\"code\":606,\"msg\":\"Email is already in use.\"}"
	       }
	*/

	url := fmt.Sprintf("%s/member/user-management/users/%s?serviceid=https://mw.myabcwallet.com", getBaseURL(), email)

	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return res.StatusCode != http.StatusOK
}

type registerRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Code       string `json:"verification_code"`
	Overage    int    `json:"overage"`
	Agree      int    `json:"agree"`
	Collect    int    `json:"collect"`
	ThirdParty int    `json:"third_party"`
	Advertise  int    `json:"advertise"`
	Serviceid  string `json:"serviceid"`
}

func register_email_user(email, encryptedPassword, vrificationCode, channelID, auth string, overage, agree, collect, thirdParty, advertise int) {
	/*
	   회원 가입

	   성공시 오류 없이 종료

	   Args:
	       email (str): 사용자 이메일
	       encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
	       verification_code (str): 인증 코드. 이메일로 전송된 인증 코드를 입력합니다.
	       channel_id (str): 보안 채널 ID.  # (2)
	       auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.
	       overage (int): 14세 이상 사용자 동의
	       agree (int): 서비스 이용 약관 동의
	       collect (int): 개인정보 수집 및 이용 동의
	       third_party (int): 제3자 정보 제공 동의
	       advertise (int): 광고성 정보 수신 동의
	*/

	url := fmt.Sprintf("%s/member/user-management/users/v2/adduser", getBaseURL())
	data := registerRequest{
		Username:   email,
		Password:   encryptedPassword,
		Code:       vrificationCode,
		Overage:    overage,
		Agree:      agree,
		Collect:    collect,
		ThirdParty: thirdParty,
		Advertise:  advertise,
		Serviceid:  "https://mw.myabcwallet.com",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal()
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal()
	}

	// 헤더 설정
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
	req.Header.Set("Secure-Channel", channelID)

	// HTTP 클라이언트 생성 및 요청 전송
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal()
	}
	defer resp.Body.Close()

	// 성공이 아닐 경우 예외처리
	if resp.StatusCode != http.StatusOK {
		log.Fatal()
	}
}

func sendCode(email, lang, template string) {
	url, err := url.Parse(fmt.Sprintf("%s/member/mail-service/%s/sendcode", getBaseURL(), email))
	if err != nil {
		log.Fatal()
	}

	q := url.Query()
	q.Add("lang", lang)
	q.Add("template", template)

	url.RawQuery = q.Encode()

	resp, err := http.Get(url.String())
	if err != nil {
		log.Fatal()
	}
	defer resp.Body.Close()

	// 성공이 아닐 경우 예외처리
	if resp.StatusCode != http.StatusOK {
		log.Fatal()
	}
}
