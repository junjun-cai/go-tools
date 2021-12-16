// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/16 15:01:11
// * File: cbc.go
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
// *    -create: 2021/12/16 15:35:25 ColeCai.
// ***********************************************************************************************
func CBCEncrypt(block cipher.Block, src, iv []byte, padding PaddingT) ([]byte, error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encrypted := make([]byte, len(src))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypted, src)
	return encrypted, nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 15:37:11 ColeCai.
// ***********************************************************************************************
func CBCDecrypt(block cipher.Block, src, iv []byte, padding PaddingT) ([]byte, error) {
	decrypted := make([]byte, len(src))

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decrypted, src)
	return UnPadding(padding, decrypted)
}
