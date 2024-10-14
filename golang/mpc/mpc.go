// mpc.go = WAAS 지갑 생성/복구 API 사용 예제
package mpc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	WID                        string          `json:"wid"`
	Email                      string          `json:"email"`
	Accounts                   []WalletAccount `json:"accounts"`
	Favorites                  []string        `json:"favorites"`
	Autoconfirms               []string        `json:"autoconfirms"`
	TwoFactorEnabled           bool            `json:"twoFactorEnabled"`
	TwoFactorResetRetryCount   int             `json:"twoFactorResetRetryCount"`
	TwoFactorRetryFreezEndTime int             `json:"twoFactorRetryFreezeEndTime"`
	TwoFactorFreezeEndTime     int             `json:"twoFactorFreezeEndTime"`
}

type GetWalletResult struct {
	UID                   string `json:"uid"`
	WID                   string `json:"wid"`
	SID                   string `json:"sid"`
	Pvencstr              string `json:"pvencstr"`
	EncryptDevicePassword string `json:"encryptDevicePassword"`
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
