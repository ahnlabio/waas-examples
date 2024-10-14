package signup

// signup.go - WAAS 회원 가입 API 사용 예제

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	securechannel "github.com/ahnlabio/waas-example.git/golang/secureChannel"
)

/*
	해당 예제는 정상동작하는 상황을 가정하고, 에러 처리를 따로하지 않음
	구현시에 에러 및 예외처리 적용 필요
*/

const WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"

// 필수 함수 아님. 유틸성 함수
func getBaseURL() string {
	waas_base_url, isExistEnv := os.LookupEnv("WAAS_BASE_URL")
	if !isExistEnv {
		waas_base_url = WAAS_BASE_URL
	}

	return waas_base_url
}

func IsExistUser(email string) bool {
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

	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	return resp.StatusCode != http.StatusOK
}

func RegisterEmailUser(email, encryptedPassword, verificationCode, channelID, auth string, overage, agree, collect, thirdParty, advertise int) {
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

	urlStr := fmt.Sprintf("%s/member/user-management/users/v2/adduser", getBaseURL())
	formData := url.Values{
		"username":    {email},
		"password":    {encryptedPassword},
		"code":        {verificationCode},
		"overage":     {strconv.Itoa(overage)},
		"agree":       {strconv.Itoa(agree)},
		"collect":     {strconv.Itoa(collect)},
		"third_party": {strconv.Itoa(thirdParty)},
		"advertise":   {strconv.Itoa(advertise)},
		"serviceid":   {"https://mw.myabcwallet.com"},
	}

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatal(err)
	}

	// 헤더 설정
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
	req.Header.Set("Secure-Channel", channelID)

	// HTTP 클라이언트 생성 및 요청 전송
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// 성공이 아닐 경우 예외처리
	if resp.StatusCode != http.StatusOK {
		log.Fatal(resp.StatusCode, resp)
	}
}

type verifyCodeType string

const (
	authCode           verifyCodeType = "verify"
	changePasswordCode verifyCodeType = "changepassword"
	initPasswordCode   verifyCodeType = "initpassword"
)

func SendVerificationCode(email, lang string) {
	/*
	   사용자 이메일로 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.

	*/
	sendCode(email, lang, authCode)
}

func SendChangePasswordCode(email, lang string) {
	/*
	   사용자 이메일로 패스워드 변경 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/

	sendCode(email, lang, changePasswordCode)
}

func SendResetPasswordCode(email, lang string) {
	/*
	   사용자 이메일로 패스워드 초기화 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/

	sendCode(email, lang, initPasswordCode)
}

func sendCode(email, lang string, template verifyCodeType) {
	url, err := url.Parse(fmt.Sprintf("%s/member/mail-service/%s/sendcode", getBaseURL(), email))
	if err != nil {
		log.Fatal()
	}

	q := url.Query()
	q.Add("lang", lang)
	q.Add("template", string(template))

	url.RawQuery = q.Encode()

	resp, err := http.Get(url.String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// 성공이 아닐 경우 예외처리
	if resp.StatusCode != http.StatusOK {
		log.Fatal(resp.StatusCode)
	}
}

func VerifyCode(email, code string) bool {
	/*
	   사용자가 입력한 코드가 올바른지 확인합니다.

	   send_verification_code, send_auth_code, send_password_reset_code 함수로 전송된 코드를 확인합니다.

	   Args:
	       email (str): 사용자 이메일 주소.
	       code (str): 사용자가 입력한 코드.

	   Returns:
	       bool: 사용자가 입력한 코드가 올바른 경우 True, 그렇지 않은 경우 False.

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/

	urlStr := fmt.Sprintf("%s/member/mail-service/%s/verifycode", getBaseURL(), email)
	formData := url.Values{
		"code":      {code},
		"serviceid": {"https://mw.myabcwallet.com"},
	}

	resp, err := http.PostForm(urlStr, formData)
	if err != nil {
		log.Fatal()
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func SignupScenario() {
	email := "email@email.com"              // 사용자 이메일
	password := "password"                  // 사용자 비밀번호
	clientID := "Client ID"                 // 발급받은 Client ID
	clientSecret := "Client Secret"         // 발급받은 Client Secret
	verificationCode := "verifiaction code" // 사용자가 입력한 인증 코드

	// 이미 가입된 사용자인지 확인합니다.
	if IsExistUser(email) {
		log.Fatalf("%s is already exist user \n", email)
	}

	fmt.Printf("%s is not exist\n", email)

	// 이메일로 인증 코드를 전송합니다.
	SendVerificationCode(email, "en")
	fmt.Println("verification code sent")

	// 사용자가 입력한 인증 코드가 올바른지 확인합니다.
	// 인증코드를 발송한 다음 사용자로부터 verification_code 를 입력 받습니다.
	if !VerifyCode(email, verificationCode) {
		log.Fatal("Invalid code", email, verificationCode)
		return
	}

	// 사용자의 비밀번호를 암호화합니다.
	secureChannelRes := securechannel.CreateSecureChannel()
	encryptedPassword := securechannel.Encrypt(secureChannelRes, password)

	// 사용자의 동의를 받습니다.
	overage := 1
	agree := 1
	collect := 1
	thirdParty := 1
	advertise := 1

	// Client ID / Client Secret
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))

	// 사용자를 등록합니다
	RegisterEmailUser(email, encryptedPassword, verificationCode, secureChannelRes.ChannelID, auth, overage, agree, collect, thirdParty, advertise)
	fmt.Println("success signup")

	existResult := IsExistUser(email)
	fmt.Printf("%s is exist: %v\n", email, existResult)
}

/*
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
2.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
*/
