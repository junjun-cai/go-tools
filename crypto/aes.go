// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/15 10:20:44
// * File: utils.go
// * Proj: go-tools
// * Pack: utils
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func AesCBCEncrypt(decrypted, aesKey []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockSize := ciphers.BlockSize()
	decrypted = PKCS7Padding(decrypted, blockSize)
	blockMode := cipher.NewCBCEncrypter(ciphers, aesKey[:blockSize])
	encrypted := make([]byte, len(decrypted))
	blockMode.CryptBlocks(encrypted, decrypted)
	return encrypted, nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func AesCBCDecrypt(encrypted, aesKey []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockSize := ciphers.BlockSize()
	blockMode := cipher.NewCBCDecrypter(ciphers, aesKey[:blockSize])
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}
