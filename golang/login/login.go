// login.go - WAAS 로그인 API 사용 예제
package login

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	securechannel "github.com/ahnlabio/waas-example.git/golang/secureChannel"
	"github.com/golang-jwt/jwt"
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

type EmailLoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiredIn    int    `json:"expired_in"`
}

// JWKKey는 JWK 키의 구조체를 정의합니다.
type JWKKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKDict는 JWK 키 목록을 포함하는 구조체를 정의합니다.
type JWKDict struct {
	Keys []JWKKey `json:"keys"`
}

func EmailLogin(email, encryptedPassword, secureChannelID, auth string) EmailLoginResult {
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

	var result EmailLoginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("Failed to decode response:", err)
	}

	return result
}

func RefreshToken(refreshToken, auth string) EmailLoginResult {
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

	var result EmailLoginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("Failed to decode response:", err)
	}

	return result
}

func VerifyToken(token string) bool {
	/*
		Token 을 검증합니다.

		1. Token 으로부터 user_pool_id 를 추출합니다.

		2. user_pool_id 를 사용하여 JWK 목록을 불러옵니다.

		3. Token header 의 kid 값과 일치하는 JWK 를 찾아 token 을 검증합니다.

		jwks.json example:
		>>> {
			"keys": [
				{
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"kid": "0",
					"x": "ZrVThPhiQSQw1YQcuXjD1qm2stKQty2N1L8gnWDVtzU",
					"y": "B6nqJgdH00TIPJkINiT6JzfDfteKVLYtP0x3NuaCpbY",
					"alg": "ES256",
				}
			]
		}

		decoded_token data example:
		>>> {
			"sub": "85abcd789a0749e0b8de39226c05f81c",
			"aud": "https://mw.myabcwallet.com",
			"iss": "https://dev-api.id.myabcwallet.com/266021e24dd0bfaaa96f2b5e21d7c800",
			"pid": "5babdf06-2a5c-4d17-88f5-2998a3db7e21",
			"exp": 1727416466,
			"iat": 1727415866,
			"jti": "bc5c7a5f29684063bdd332b9262d1c7b",
			"user-agent": "python-requests/2.32.3",
		}

		Args:
		token (str): 검증할 JWT token.

		Returns:
		bool: 검증 결과.
	*/

	// JWT 토큰 디코딩 (서명 검증 없이)
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		log.Fatalf("Failed to parse token: %v", err)
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		iss := claims["iss"].(string)
		parsedURL, err := url.Parse(iss)
		if err != nil {
			log.Fatalf("Failed to parse issuer URL: %v", err)
		}
		userPoolID := strings.TrimPrefix(parsedURL.Path, "/")

		resp, err := http.Get(fmt.Sprintf("%s/jwk/key-service/%s/.well-known/jwks.json", getBaseURL(), userPoolID))
		if err != nil {
			log.Fatal("Failed to get jwt")
		}

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Request failed with status: %d", resp.StatusCode)
		}

		var result JWKDict
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			log.Fatal("Failed to decode response:", err)
		}

		// JWT 헤더에서 kid 값 추출
		jwtHeader := parsedToken.Header
		kid, ok := jwtHeader["kid"].(string)
		if !ok {
			log.Fatalf("Failed to get kid from token header")
		}

		// kid 값이 일치하는 첫 번째 키 찾기
		var foundKey *JWKKey
		for _, key := range result.Keys {
			if key.Kid == kid {
				foundKey = &key
				break
			}
		}

		return foundKey != nil
	} else {
		log.Fatalf("Invalid token claims")
	}

	return false
}

func LoginScenario() {
	email := "email"                // 사용자 이메일
	password := "password"          // 사용자 비밀번호
	clientID := "Client ID"         // 발급받은 Client ID
	clientSecret := "Client Secret" // 발급받은 Client Secret

	// Secure Channel 생성
	secureChannelRes := securechannel.CreateSecureChannel()

	// password 는 Secure Channel 암호화가 필요합니다
	encryptedPassword := securechannel.Encrypt(secureChannelRes, password)

	// Client ID / Client Secret
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))

	// 로그인
	loginResult := EmailLogin(email, encryptedPassword, secureChannelRes.ChannelID, string(auth))

	// 성공 시 jwt token 생성됨
	fmt.Println("access token : ", loginResult.AccessToken)
	fmt.Println("refresh token : ", loginResult.RefreshToken)

	// jwt token 검증
	verifyResult := VerifyToken(loginResult.AccessToken)
	fmt.Println("verify result : ", verifyResult)

	// refresh token을 이용하여 token 재발급
	refreshTokenResult := RefreshToken(loginResult.RefreshToken, string(auth))

	// 성공 시 jwt token 재발급됨
	fmt.Println("access token : ", refreshTokenResult.AccessToken)
	fmt.Println("refresh token : ", refreshTokenResult.RefreshToken)

	// jwt token 검증
	verifyResult = VerifyToken(refreshTokenResult.AccessToken)
	fmt.Println("verify result : ", verifyResult)
}

/*
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
2.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
*/
