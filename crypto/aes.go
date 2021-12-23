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
// * 	-AesCBCEncrypt(decrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * 	-AesCBCDecrypt(encrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * 	-AesECBEncrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-AesECBDecrypt(encrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-AesCFBEncrypt(decrypted, aesKey, iv []byte) ([]byte, error)
// *	-AesCFBDecrypt(encrypted, aesKey, iv []byte) ([]byte, error)
// * 	-AesOFBEncrypt(encrypted, aesKey, iv []byte) ([]byte, error)
// * 	-AesOFBDecrypt(encrypted, aesKey, iv []byte) ([]byte, error)
// * 	-AesCTREncrypt(decrypted, aesKey, iv []byte) ([]byte, error)
// * 	-AesCTRDecrypt(decrypted, aesKey, iv []byte) ([]byte, error)
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

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/20 10:11:36 ColeCai.
// ***********************************************************************************************
func AesCFBEncrypt(decrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CFBEncrypt(ciphers, decrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/20 10:13:11 ColeCai.
// ***********************************************************************************************
func AesCFBDecrypt(encrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CFBDecrypt(ciphers, encrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/22 10:44:05 ColeCai.
// ***********************************************************************************************
func AesOFBEncrypt(encrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return OFBCrypto(ciphers, encrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/22 10:44:57 ColeCai.
// ***********************************************************************************************
func AesOFBDecrypt(encrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return OFBCrypto(ciphers, encrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/22 11:10:11 ColeCai.
// ***********************************************************************************************
func AesCTREncrypt(decrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CTRCrypto(ciphers, decrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/22 11:10:52 ColeCai.
// ***********************************************************************************************
func AesCTRDecrypt(decrypted, aesKey, iv []byte) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return CTRCrypto(ciphers, decrypted, iv)
}
