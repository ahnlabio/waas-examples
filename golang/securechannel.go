// securechannel.go - WAAS Secure Channel API 사용 예제

package main

import (
	"bytes"
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
	"math/big"
	"net/http"
	"net/url"
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

type createSecureChannelRequest struct {
	PublicKey string `json:"pubkey"`
	Plain     string `json:"plain"`
}

func createSecureChannel(secureChannelMessage string) SecureChannel {
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
	secureChannelMessage = "conanTestGolang" // (1)

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
	// ECDSA 키 쌍 생성
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal()
	}
	publicKey := &privateKey.PublicKey

	// KeyPair 인스턴스 생성 및 반환
	return KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

func verifySecureChannel(secureChannel SecureChannel) bool {
	return secureChannel.Message == decrypt(secureChannel, secureChannel.Encrypted)
}

func decrypt(secureChannel SecureChannel, encryptedMessage string) string {
	cipherBlock := getAESCipher(secureChannel.PrivateKey, secureChannel.ServerPublicKey)

	encMsg, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		log.Fatal("fail to decode message", err)
	}

	iv := encMsg[:aes.BlockSize]
	ciphertext := encMsg[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(cipherBlock, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	unpaddedMsg, err := pkcs7Unpad(decrypted, aes.BlockSize)
	if err != nil {
		log.Fatal("fail to unpad ", err, aes.BlockSize, decrypted, ciphertext, encMsg)
	}

	return string(unpaddedMsg)
}

// 암호화 함수
func encrypt(secureChannel SecureChannel, message string) string {
	cipherBlock := getAESCipher(secureChannel.PrivateKey, secureChannel.ServerPublicKey)

	paddedMsg := pkcs7Pad([]byte(message), aes.BlockSize)
	ciphertext := make([]byte, len(paddedMsg))
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatal()
	}

	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	mode.CryptBlocks(ciphertext, paddedMsg)

	encMsg := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(encMsg)
}

func getAESCipher(privateKey, publicKey string) cipher.Block {
	// 16진수 문자열을 바이트 배열로 변환
	pubKeyBytes, _ := hex.DecodeString(publicKey)
	privKeyBytes, _ := hex.DecodeString(privateKey)

	// 공개 키와 개인 키 복원
	pubKeyX, pubKeyY := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: pubKeyX, Y: pubKeyY}
	privKey := &ecdsa.PrivateKey{PublicKey: *pubKey, D: new(big.Int).SetBytes(privKeyBytes)}

	// 공유 비밀 생성
	secret, err := sharedSecret(privKey, pubKey)
	if err != nil {
		log.Fatalf("Error generating shared secret: %v", err)
	}

	ecdh.P256().GenerateKey()

	// AES 키와 IV 생성
	aesKey := secret[:16]
	aes.NewCipher()
	// AES 암호화 블록 생성
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatalf("Error creating AES cipher: %v", err)
	}

	return block
}

// sharedSecret 함수 정의
func sharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes(), nil
}

// PKCS7 패딩 함수
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding data size")
	}
	padding := int(data[length-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:length-padding], nil
}

func secureChannelScenario() {
	secureChannelMSG := "ahnlabblockchaincompany"

	// Secure channel 생성
	secureChannel := createSecureChannel(secureChannelMSG)
	fmt.Println("생성된 secure channel 객체 : ", secureChannel)

	// Secure Channel 검증
	verifyResult := verifySecureChannel(secureChannel)
	fmt.Printf("Secure Channel verify result: %v", verifyResult)

	// Secure Channel 을 사용한 메시지 암복호화
	message := "hello, waas"
	encryptedMessage := encrypt(secureChannel, message)
	decryptedMessage := decrypt(secureChannel, encryptedMessage)

	fmt.Printf("message encrypt result: %v", (encryptedMessage == decryptedMessage))
	fmt.Print("hello worrrrr")
}

/*
1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
*/
