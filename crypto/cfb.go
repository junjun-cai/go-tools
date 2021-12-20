// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/16 15:43:46
// * File: cfb.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/cipher"

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 15:43:59 ColeCai.
// ***********************************************************************************************
func CFBEncrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 15:55:35 ColeCai.
// ***********************************************************************************************
func CFBDecrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(decrypted, src)
	return decrypted, nil
}
