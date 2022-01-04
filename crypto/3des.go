// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/31 10:12:05
// * File: 3des.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * 	-DesCBCEncrypt(decrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * 	-DesCBCDecrypt(encrypted, desKey, iv []byte, padding PaddingT) ([]byte, error)
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/des"

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey must 24 bytes, iv must 8 bytes.
// * HISTORY:
// *    -create: 2022/12/31 10:13:17 ColeCai.
// ***********************************************************************************************
func Des3CBCEncrypt(decrypted, desKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CBCEncrypt(ciphers, decrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-deskey must 24 bytes, iv must 8 bytes.
// * HISTORY:
// *    -create: 2022/12/31 10:14:23 ColeCai.
// ***********************************************************************************************
func Des3CBCDecrypt(encrypted, desKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return CBCDecrypt(ciphers, encrypted, iv, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/04 10:20:50 ColeCai.
// ***********************************************************************************************
func Des3ECBEncrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(ciphers, decrypted, padding)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/04 10:22:47 ColeCai.
// ***********************************************************************************************
func Des3ECBDecrypt(encrypted, desKey []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return ECBDecrypt(ciphers, encrypted, padding)
}
