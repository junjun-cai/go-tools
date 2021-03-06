// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/16 16:37:18
// * File: ofb.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"crypto/cipher"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 16:37:58 ColeCai.
// ***********************************************************************************************
func OFBCrypto(block cipher.Block, src, iv []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	ofb := cipher.NewOFB(block, iv)
	ofb.XORKeyStream(dst, src)
	return dst, nil
}
