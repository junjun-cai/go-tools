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
func PKCS7Padding(decrypted []byte, blockSize int) []byte {
	padding := blockSize - len(decrypted)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(decrypted, padText...)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func PKCS7UnPadding(decrypted []byte) []byte {
	length := len(decrypted)
	unPadding := int(decrypted[length-1])
	return decrypted[:(length - unPadding)]
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-aesKey must 16,24 or 32 bytes.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 11:25:32 ColeCai. encrypt with customize iv.
// ***********************************************************************************************
func AesCBCEncrypt(decrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockSize := ciphers.BlockSize()
	decrypted = PKCS7Padding(decrypted, blockSize)
	blockMode := cipher.NewCBCEncrypter(ciphers, iv)
	encrypted := make([]byte, len(decrypted))
	blockMode.CryptBlocks(encrypted, decrypted)
	return encrypted, nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-aesKey must 16,24 or 32 bytes.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 11:26:42 ColeCai. decrypt with customize iv.
// ***********************************************************************************************
func AesCBCDecrypt(encrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(ciphers, iv)
	decrypted := make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	decrypted = PKCS7UnPadding(decrypted)
	return decrypted, nil
}
