// package main

// import (
//     "crypto/aes"
//     "crypto/cipher"
//     "crypto/rand"
//     "encoding/hex"
//     "fmt"
//     "log"
// )

// // PKCS7 패딩 함수
// func pkcs7Pad(data []byte, blockSize int) []byte {
//     padding := blockSize - len(data)%blockSize
//     padtext := bytes.Repeat([]byte{byte(padding)}, padding)
//     return append(data, padtext...)
// }

// // PKCS7 언패딩 함수
// func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
//     length := len(data)
//     if length == 0 {
//         return nil, errors.New("unpad error: input is empty")
//     }
//     if length%blockSize != 0 {
//         return nil, errors.New("unpad error: input is not a multiple of block size")
//     }
//     unpadding := int(data[length-1])
//     if unpadding > blockSize || unpadding == 0 {
//         return nil, errors.New("unpad error: invalid padding size")
//     }
//     return data[:(length - unpadding)], nil
// }

// func main() {
//     // 예제 키와 IV 생성
//     bytesSecret := make([]byte, 32)
//     if _, err := rand.Read(bytesSecret); err != nil {
//         log.Fatalf("Failed to generate secret: %v", err)
//     }

//     key := bytesSecret[0:16]
//     iv := bytesSecret[16:32]

//     // AES 블록 암호화 객체 생성
//     block, err := aes.NewCipher(key)
//     if err != nil {
//         log.Fatalf("Failed to create AES cipher: %v", err)
//     }

//     // CBC 모드 암호화 객체 생성
//     encrypter := cipher.NewCBCEncrypter(block, iv)

//     // 암호화할 데이터
//     plaintext := []byte("your plaintext message")
//     paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)
//     ciphertext := make([]byte, len(paddedPlaintext))
//     encrypter.CryptBlocks(ciphertext, paddedPlaintext)

//     fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

//     // CBC 모드 복호화 객체 생성
//     decrypter := cipher.NewCBCDecrypter(block, iv)
//     decrypted := make([]byte, len(ciphertext))
//     decrypter.CryptBlocks(decrypted, ciphertext)
//     unpaddedDecrypted, err := pkcs7Unpad(decrypted, aes.BlockSize)
//     if err != nil {
//         log.Fatalf("Failed to unpad decrypted message: %v", err)
//     }

//	    fmt.Printf("Decrypted: %s\n", string(unpaddedDecrypted))
//	}
package main
