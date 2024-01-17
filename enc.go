package licenselib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// hashKey hashes the given key to a 32-byte key using SHA-256
func hashKey(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

// reverseBytes reverses a byte array
func reverseBytes(data []byte) []byte {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	return data
}

// Encode encrypts the text with AES and encodes it in Base64
func Encode(secretKey string, text string) string {
	key := hashKey(secretKey)

	// Layer 1: AES Encryption with hashed key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize] // using a zeroed IV for simplicity
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Layer 2: AES Encryption with reversed hashed key
	reversedKey := reverseBytes(hashKey(secretKey))
	block, err = aes.NewCipher(reversedKey)
	if err != nil {
		panic(err.Error())
	}

	layer2Ciphertext := make([]byte, aes.BlockSize+len(ciphertext))
	ivLayer2 := layer2Ciphertext[:aes.BlockSize] // New IV for second layer
	stream = cipher.NewCFBEncrypter(block, ivLayer2)
	stream.XORKeyStream(layer2Ciphertext[aes.BlockSize:], ciphertext)

	// Layer 3: Base64 Encoding
	finalCiphertext := base64.StdEncoding.EncodeToString(layer2Ciphertext)
	return finalCiphertext
}

// Decode decrypts the Base64-encoded and AES-encrypted text
func Decode(secretKey string, encodedText string) (string, error) {
	key := hashKey(secretKey)

	// Layer 3: Base64 Decoding
	decodedText, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		return "", err
	}

	// Layer 2: AES Decryption with reversed hashed key
	if len(decodedText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	ivLayer2 := decodedText[:aes.BlockSize]
	layer2Ciphertext := make([]byte, len(decodedText)-aes.BlockSize)
	reversedKey := reverseBytes(key)
	block, err := aes.NewCipher(reversedKey)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCFBDecrypter(block, ivLayer2)
	stream.XORKeyStream(layer2Ciphertext, decodedText[aes.BlockSize:])

	// Layer 1: AES Decryption with original hashed key
	if len(layer2Ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	ivLayer1 := layer2Ciphertext[:aes.BlockSize]
	finalPlaintext := make([]byte, len(layer2Ciphertext)-aes.BlockSize)
	block, err = aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	stream = cipher.NewCFBDecrypter(block, ivLayer1)
	stream.XORKeyStream(finalPlaintext, layer2Ciphertext[aes.BlockSize:])

	return string(finalPlaintext), nil
}
