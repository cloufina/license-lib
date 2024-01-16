package licenselib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math"
	"strings"
)

func EncryptAES(key []byte, plaintext string) []byte {
	block, err := aes.NewCipher(key)
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
	return aesGcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

func DecryptAES(key, encrypted []byte) string {
	block, err := aes.NewCipher(key)
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
