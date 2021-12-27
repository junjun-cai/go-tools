// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/23 10:06:49
// * File: des.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * 	-DesCBCEncrypt(decrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * 	-DesCBCDecrypt(encrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * 	-DesECBEncrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-DesECBDecrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-DesCFBEncrypt(decrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesCFBDecrypt(encrypted, desKey, iv []byte) ([]byte, error)
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"crypto/des"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey and iv length must equal 8. if not DesCBCEncrypt will panic.
// * HISTORY:
// *    -create: 2021/12/23 10:06:54 ColeCai.
// ***********************************************************************************************
func DesCBCEncrypt(decrypted []byte, desKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CBCEncrypt(ciphers, decrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey and iv length must equal 8. if not DesCBCDecrypt will panic.
// * HISTORY:
// *    -create: 2021/12/23 10:09:12 ColeCai.
// ***********************************************************************************************
func DesCBCDecrypt(encrypted []byte, desKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CBCDecrypt(ciphers, encrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey length must equal 8. if not DesCBCDecrypt will panic.
// * HISTORY:
// *    -create: 2021/12/24 10:15:55 ColeCai.
// ***********************************************************************************************
func DesECBEncrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(ciphers, decrypted, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey length must equal 8. if not DesCBCDecrypt will panic.
// * HISTORY:
// *    -create: 2021/12/24 10:18:16 ColeCai.
// ***********************************************************************************************
func DesECBDecrypt(encrypted, desKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return ECBDecrypt(ciphers, encrypted, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/25 15:04:28 ColeCai.
// ***********************************************************************************************
func DesCFBEncrypt(decrypted, desKey, iv []byte) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CFBEncrypt(ciphers, decrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/25 15:05:28 ColeCai.
// ***********************************************************************************************
func DesCFBDecrypt(encrypted, desKey, iv []byte) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CFBDecrypt(ciphers, encrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/27 09:39:58 ColeCai.
// ***********************************************************************************************
func DesOFBEncrypt(encrypted, desKey, iv []byte) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return OFBCrypto(ciphers, encrypted, iv)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/27 09:40:51 ColeCai.
// ***********************************************************************************************
func DesOFBDecrypt(decrypted, desKey, iv []byte) ([]byte, error) {
	ciphers, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return OFBCrypto(ciphers, decrypted, iv)
}
