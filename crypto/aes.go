// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/15 10:20:44
// * File: aes.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"crypto/aes"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-aesKey must 16,24 or 32 bytes.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 11:25:32 ColeCai. encrypt with customize iv.
// *	-update: 2021/12/16 14:37:20 ColeCai. encrypt with customize padding type.
// * 	-update: 2021/12/16 15:40:49 ColeCai. make cbc as public module.
// ***********************************************************************************************
func AesCBCEncrypt(decrypted, aesKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CBCEncrypt(ciphers, decrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-aesKey must 16,24 or 32 bytes.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 11:26:42 ColeCai. decrypt with customize iv.
// *	-update: 2021/12/16 14:37:58 ColeCai. decrypt with customize padding type.
// * 	-update: 2021/12/16 15:41:37 ColeCai. make cbc as public module.
// ***********************************************************************************************
func AesCBCDecrypt(encrypted, aesKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CBCDecrypt(ciphers, encrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/17 10:02:44 ColeCai.
// ***********************************************************************************************
func AesECBEncrypt(decrypted, aesKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(ciphers, decrypted, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/17 10:04:06 ColeCai.
// ***********************************************************************************************
func AesECBDecrypt(encrypted, aesKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return ECBDecrypt(ciphers, encrypted, padding)
}
