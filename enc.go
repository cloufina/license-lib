package licenselib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"strings"
)

// hashKey hashes the given key to a 32-byte key using SHA-256
func hashKey(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

// reverseBytes reverses a byte array
func reverseBytes(data []byte) []byte {
	reversedData := make([]byte, len(data))
	copy(reversedData, data)
	for i, j := 0, len(reversedData)-1; i < j; i, j = i+1, j-1 {
		reversedData[i], reversedData[j] = reversedData[j], reversedData[i]
	}
	return reversedData
}

// aesEncrypt performs AES encryption on the given plaintext using the provided key
func aesEncrypt(key []byte, plaintext string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return aesGcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

// aesDecrypt performs AES decryption on the given ciphertext using the provided key
func aesDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGcm.Open(nil, nonce, ciphertext, nil)
}

// Encode encrypts the text with AES and encodes it in Base64
func Encode(secretKey string, text string) string {
	key := hashKey(secretKey)

	// Layer 1: AES Encryption with original hashed key
	ciphertext := aesEncrypt(key, text)

	// Layer 2: AES Encryption with reversed hashed key
	reversedKey := reverseBytes(key)
	ciphertext = aesEncrypt(reversedKey, string(ciphertext))

	// Layer 3: AES Encryption with first half of the original hashed key rehashed
	firstHalfKey := hashKey(string(key[:len(key)/2]))
	ciphertext = aesEncrypt(firstHalfKey, string(ciphertext))

	// Layer 4: AES Encryption with second half of the original hashed key rehashed
	secondHalfKey := hashKey(string(key[len(key)/2:]))
	ciphertext = aesEncrypt(secondHalfKey, string(ciphertext))

	// Layer 5: Base64 Encoding
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decode decrypts the Base64-encoded and AES-encrypted text
func Decode(secretKey string, encodedText string) (string, error) {
	key := hashKey(secretKey)

	// Layer 5: Base64 Decoding
	decodedText, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		return "", err
	}

	// Layer 4: AES Decryption with second half of the original hashed key rehashed
	secondHalfKey := hashKey(string(key[len(key)/2:]))
	plaintext, err := aesDecrypt(secondHalfKey, decodedText)
	if err != nil {
		return "", err
	}

	// Layer 3: AES Decryption with first half of the original hashed key rehashed
	firstHalfKey := hashKey(string(key[:len(key)/2]))
	plaintext, err = aesDecrypt(firstHalfKey, plaintext)
	if err != nil {
		return "", err
	}

	// Layer 2: AES Decryption with reversed hashed key
	reversedKey := reverseBytes(key)
	plaintext, err = aesDecrypt(reversedKey, plaintext)
	if err != nil {
		return "", err
	}

	// Layer 1: AES Decryption with original hashed key
	plaintext, err = aesDecrypt(key, plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func EncryptAES(key, plaintext string) []byte {
	key2 := hashKey(key)
	block, err := aes.NewCipher(key2)
	if err != nil {
		panic(err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	enc1 := aesGcm.Seal(nonce, nonce, []byte(plaintext), nil)
	//end encryption layer 1 and start encryption layer 2
	key3 := reverseBytes(key2)
	block, err = aes.NewCipher(key3)
	if err != nil {
		panic(err)
	}
	aesGcm, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce = make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	enc1 = aesGcm.Seal(nonce, nonce, enc1, nil)
	return enc1
}

func DecryptAES(key string, encrypted []byte) string {
	key2 := reverseBytes(hashKey(key))
	block, err := aes.NewCipher(key2)
	if err != nil {
		panic(err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonceSize := aesGcm.NonceSize()
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	// end decryption layer 2 start decryption layer 1
	key2 = reverseBytes(key2)
	block, err = aes.NewCipher(key2)
	if err != nil {
		panic(err)
	}
	aesGcm, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonceSize = aesGcm.NonceSize()
	nonce, ciphertext = plaintext[:nonceSize], plaintext[nonceSize:]
	plaintext, err = aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}

func StrPad(input string, padLength int, padString string, padType string) string {
	var output string

	inputLength := len(input)
	padStringLength := len(padString)

	if inputLength >= padLength {
		return input[:padLength]
	}

	repeat := math.Ceil(float64(1) + (float64(padLength-padStringLength))/float64(padStringLength))

	switch padType {
	case "RIGHT":
		output = input + strings.Repeat(padString, int(repeat))
		output = output[:padLength]
	case "LEFT":
		output = strings.Repeat(padString, int(repeat)) + input
		output = output[len(output)-padLength:]
	case "BOTH":
		length := (float64(padLength - inputLength)) / float64(2)
		repeat = math.Ceil(length / float64(padStringLength))
		output = strings.Repeat(padString, int(repeat))[:int(math.Floor(float64(length)))] + input + strings.Repeat(padString, int(repeat))[:int(math.Ceil(float64(length)))]
	}

	return output
}
