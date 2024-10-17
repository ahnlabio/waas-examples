// mpc.go = WAAS 지갑 생성/복구 API 사용 예제
package mpc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ahnlabio/waas-example.git/golang/login"                       // (2)
	securechannel "github.com/ahnlabio/waas-example.git/golang/secureChannel" // (1)
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

type WalletAccount struct {
	ID         string `json:"id"`
	SID        string `json:"sid"`
	ETHAddress string `json:"ethAddress"`
	Icon       string `json:"icon"`
	Name       string `json:"name"`
	Signer     string `json:"signer"`
	PublicKey  string `json:"pubkey"`
}

type WalletInfo struct {
	ID                         string          `json:"_id"`
	UID                        string          `json:"uid"`
	WID                        int             `json:"wid"`
	Email                      string          `json:"email"`
	Accounts                   []WalletAccount `json:"accounts"`
	Favorites                  []string        `json:"favorites"`
	Autoconfirms               []string        `json:"autoconfirms"`
	TwoFactorEnabled           bool            `json:"twoFactorEnabled"`
	TwoFactorResetRetryCount   int             `json:"twoFactorResetRetryCount"`
	TwoFactorRetryFreezEndTime int             `json:"twoFactorRetryFreezeEndTime"`
	TwoFactorFreezeEndTime     int             `json:"twoFactorFreezeEndTime"`
}

func GetWalletInfo(accessToken string) WalletInfo {
	/*
		사용자 MPC 지갑을 조회합니다.

		Args:
			access_token (str): 지갑 사용자의 JWT Token

		WalletInfo example:
		>>> {
			"_id": "657bdc790b67b600128a865f",
			"uid": "d5b440b8-469b-4e16-8978-d78b73a09c4e",
			"wid": 6,
			"email": "test_0@myabcwallet.com",
			"accounts": [
				{
				"id": "0",
				"sid": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
				"ethAddress": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
				"icon": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4Hs....",
				"name": "Account 1",
				"signer": "mpc",
				"pubkey": "0x025c5d89f60eba1b8fc5c2bd2fa28eefe48f4c950815acd7...."
				}
			],
			"favorites": [],
			"autoconfirms": [],
			"twoFactorEnabled": false,
			"twoFactorResetRetryCount": 0,
			"twoFactorRetryFreezeEndTime": 0,
			"twoFactorFreezeEndTime": 0
		}
	*/

	urlStr := fmt.Sprintf("%s/wapi/v2/mpc/wallets/info", getBaseURL())
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(resp, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("fail to get wallet info: %v\n", resp)
	}

	var result WalletInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("fail to decode result %v\n", err)
	}

	return result
}

type GetWalletResult struct {
	UID                   string `json:"uid"`
	WID                   int    `json:"wid"`
	SID                   string `json:"sid"`
	Pvencstr              string `json:"pvencstr"`
	EncryptDevicePassword string `json:"encryptDevicePassword"`
}

func GetWallet(email, encryptedDevicePassowrd, channelID, accessToken string) GetWalletResult {
	/*
		사용자 고유 MPC 지갑을 생성합니다.

		사용자는 1개의 고유 지갑을 소유하게 되며, 이미 생성된 지갑이 존재하는 경우, 기존 지갑을 복구합니다.

		devicePassword는 생성 혹은 복구되는 지갑의 Key Share의 암호를 의미합니다.

		GetWalletResult example :
		>>> {
			"uid": "d5b440b8-469b-4e16-8978-d78b73a09c4e",
			"wid": 6,
			"sid": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
			"pvencstr": "0x1234567890abcdef",
			"encryptDevicePassword": "sEbZRmmOrvmMI83XugEzEVwRpwkBBCeXb4jMq1f8Wao="
		}

		Args:
			email (str): 사용자 이메일
			encrypted_device_password (str): Secure Channel로 암호화된 devicePassword
			channel_id (str): 보안 채널 ID.
			access_token (str): 지갑 사용자의 JWT Token

		Returns:
			GetWalletResult: 사용자의 MPC 지갑 정보

		Raises:
			HTTPError: 지갑 생성 요청이 실패한 경우
	*/

	urlStr := fmt.Sprintf("%s/wapi/v2/mpc/wallets", getBaseURL())
	data := url.Values{
		"email":          {email},
		"devicePassword": {encryptedDevicePassowrd},
	}

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal("Failed to create request:", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Secure-Channel", channelID)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status: %d", resp.StatusCode)
	}

	var result GetWalletResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("fail to decode result %v\n", err)
	}

	return result
}

func MPCScenario() {
	email := "email@email.com"      // 사용자 이메일
	password := "password"          // 사용자 비밀번호
	clientID := "Client ID"         // 발급받은 Client ID
	clientSecret := "Client Secret" // 발급받은 Client Secret

	// Secure Channel 생성
	secureChannelRes := securechannel.CreateSecureChannel()

	// password 는 Secure Channel 암호화가 필요합니다.
	encryptedPassword := securechannel.Encrypt(secureChannelRes, password)

	// Client ID / Client Secret
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret))) // (3)

	// 로그인
	emailLoginResult := login.EmailLogin(email, encryptedPassword, secureChannelRes.ChannelID, auth)

	// 성공시 jwt token 생성됨
	fmt.Printf("access token: %s\n", emailLoginResult.AccessToken)

	devicePassword := "password" // (4)
	encryptedDevicePassword := securechannel.Encrypt(secureChannelRes, devicePassword)

	wallet := GetWallet(email, encryptedDevicePassword, secureChannelRes.ChannelID, emailLoginResult.AccessToken)
	fmt.Printf("wallet uid: %s\n", wallet.UID)
	fmt.Printf("wallet wid: %v\n", wallet.WID)
	fmt.Printf("wallet sid: %s\n", wallet.SID)

	walletInfo := GetWalletInfo(emailLoginResult.AccessToken)
	fmt.Printf("wallet info uid: %s\n", walletInfo.UID)
	fmt.Printf("wallet info wid: %v\n", walletInfo.WID)
	fmt.Printf("wallet info sid: %s\n", walletInfo.Accounts[0].SID)
}

/*
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/secure-channel/](secure-channel.md#__tabbed_1_3))
2.  :man_raising_hand: Getting Started > Login 참고 ([getting-started/guide/login/](login.md#__tabbed_1_3))
3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
4.  :man_raising_hand: devicePassword 는 키 조각 암호화를 위해 사용됩니다. Secure Channel 암호화가 필요합니다.
*/
