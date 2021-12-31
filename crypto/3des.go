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
// * 	-DesECBEncrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-DesECBDecrypt(decrypted, desKey []byte, padding PaddingT) ([]byte, error)
// * 	-DesCFBEncrypt(decrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesCFBDecrypt(encrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesOFBEncrypt(decrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesOFBDecrypt(encrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesCTREncrypt(decrypted, desKey, iv []byte) ([]byte, error)
// * 	-DesCTRDecrypt(encrypted, desKey, iv []byte) ([]byte, error)
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/des"

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
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
