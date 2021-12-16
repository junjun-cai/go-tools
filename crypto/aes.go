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
	"crypto/aes"
	"crypto/cipher"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-aesKey must 16,24 or 32 bytes.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 11:25:32 ColeCai. encrypt with customize iv.
// *	-update: 2021/12/16 14:37:20 ColeCai. encrypt with customize padding type.
// ***********************************************************************************************
func AesCBCEncrypt(decrypted, aesKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockSize := ciphers.BlockSize()
	decrypted = Padding(padding, decrypted, blockSize)
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
// *	-update: 2021/12/16 14:37:58 ColeCai. decrypt with customize padding type.
// ***********************************************************************************************
func AesCBCDecrypt(encrypted, aesKey, iv []byte, padding PaddingT) ([]byte, error) {
	ciphers, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(ciphers, iv)
	decrypted := make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	return UnPadding(padding, decrypted)
}
