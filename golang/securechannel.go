// securechannel.go - WAAS Secure Channel API 사용 예제

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/mergermarket/go-pkcs7"
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

type SecureChannel struct {
	PrivateKey      string `json:"private_key"`
	Message         string `json:"message"`
	Encrypted       string `json:"encrypted"`
	ServerPublicKey string `json:"server_public_key"`
	ChannelID       string `json:"channel_id"`
}

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

type CreateSecureChannelResponse struct {
	PublicKey string `json:"publickey"`
	Encrypted string `json:"encrypted"`
	ChannelID string `json:"channelid"`
}

func createSecureChannel() SecureChannel {
	/*
	   생성된 공개 키와 보안 채널 메시지를 사용하여 보안 채널을 생성합니다.

	   	`WAAS_BASE_URL` 환경 변수를 사용하여 WAAS API 서버의 기본 URL을 설정할 수 있습니다.

	   	Dev : https://dev-api.waas.myabcwallet.com
	   	Production : https://api.waas.myabcwallet.com

	   	참고:
	   	https://docs.waas.myabcwallet.com/ko/getting-started/guide/secure-channel/

	   	Args:
	   	    secure_channel_message (str): 요청에 사용되는 plain 은 채널 생성 확인을 위한 임시 문자열

	   	Returns:
	   	    SecureChannel: 보안 채널 데이터.

	   	Raises:
	   	    HTTPError: 보안 채널 생성 요청이 실패한 경우.
	*/

	keyPair := createKeypair()
	// 공개 키를 바이트 배열로 변환
	publicKeyBytes := elliptic.Marshal(elliptic.P256(), keyPair.PublicKey.X, keyPair.PublicKey.Y)

	// 바이트 배열을 16진수 문자열로 인코딩
	publicKeyStr := hex.EncodeToString(publicKeyBytes)
	fmt.Println("publicKeyStr : ", publicKeyStr)
	secureChannelMessage := "ahnlabblockchaincompany" // (1)

	// 전송할 form 데이터 생성
	formData := url.Values{
		"pubkey": {publicKeyStr},
		"plain":  {secureChannelMessage},
	}

	urlStr := fmt.Sprintf("%s/secure/channel/create", getBaseURL())
	// HTTP POST 요청 보내기
	resp, err := http.PostForm(urlStr, formData)
	if err != nil {
		log.Fatalf("PostForm error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal("fail to create channel request resp.StatusCode != http.StatusOK", resp.StatusCode, resp)
	}

	var result CreateSecureChannelResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("fail to decode resp", err)
	}

	// 개인 키를 바이트 배열로 변환
	privateKeyBytes := keyPair.PrivateKey.D.Bytes()

	// 바이트 배열을 16진수 문자열로 인코딩
	privateKeyStr := hex.EncodeToString(privateKeyBytes)

	return SecureChannel{
		ChannelID:       result.ChannelID,
		Encrypted:       result.Encrypted,
		ServerPublicKey: result.PublicKey,
		Message:         secureChannelMessage,
		PrivateKey:      privateKeyStr,
	}
}

func createKeypair() KeyPair {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := &privateKey.PublicKey
	return KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

func verifySecureChannel(secureChannel SecureChannel) bool {
	decryptedMessage := decrypt(secureChannel, secureChannel.Encrypted)
	return secureChannel.Message == decryptedMessage
}

func encrypt(secureChannel SecureChannel, message string) string {
	block, iv := getAESCipher(secureChannel.PrivateKey, secureChannel.ServerPublicKey)

	paddedMsg, err := pkcs7.Pad([]byte(message), aes.BlockSize)
	if err != nil {
		log.Fatal("fail to pad message", err)
	}
	encMsg := make([]byte, len(paddedMsg))

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(encMsg, paddedMsg)
	return base64.StdEncoding.EncodeToString(encMsg)
}

func decrypt(secureChannel SecureChannel, encryptedMessage string) string {
	block, iv := getAESCipher(secureChannel.PrivateKey, secureChannel.ServerPublicKey)

	encMsg, _ := base64.StdEncoding.DecodeString(encryptedMessage)
	decryptedMsg := make([]byte, len(encMsg))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decryptedMsg, encMsg)

	unpadMSG, err := pkcs7.Unpad(decryptedMsg, aes.BlockSize)
	if err != nil {
		log.Fatal("fail to pad message", err)
	}
	return string(unpadMSG)
}

func getAESCipher(privateKeyStr, publicKeyStr string) (cipher.Block, []byte) {
	privateKeyBytes, _ := hex.DecodeString(privateKeyStr)
	publicKeyBytes, _ := hex.DecodeString(publicKeyStr)

	privateKey, _ := ecdh.P256().NewPrivateKey(privateKeyBytes)
	publicKey, _ := ecdh.P256().NewPublicKey(publicKeyBytes)

	sharedSecret, _ := privateKey.ECDH(publicKey)

	key := sharedSecret[0:16]
	iv := sharedSecret[16:32]

	block, _ := aes.NewCipher(key)
	return block, iv
}

func secureChannelScenario() {
	// Secure channel 생성
	secureChannel := createSecureChannel()

	// Secure Channel 검증
	verifyResult := verifySecureChannel(secureChannel)
	fmt.Printf("Secure Channel verify result: %v\n", verifyResult) // true 예상

	// Secure Channel 을 사용한 메시지 암복호화
	// message := "hello, waas"
	encryptedMessage := encrypt(secureChannel, secureChannel.Message)
	decryptedMessage := decrypt(secureChannel, encryptedMessage)

	fmt.Printf("message encrypt result: %v\n", (secureChannel.Message == decryptedMessage)) // true 예상
}

/*
1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
*/
