// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/16 14:16:56
// * File: utils.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"bytes"
	"github.com/pkg/errors"
)

var ErrorUnPadding = errors.New("UnPadding error")

type PaddingT string

const (
	PKCS5_PADDING PaddingT = "PKCS5"
	PKCS7_PADDING PaddingT = "PKCS7"
	ZEROS_PADDING PaddingT = "ZEROS"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// * 	-update: 2021/12/16 14:22:35 ColeCai. verify src and unPadding length.
// ***********************************************************************************************
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrorUnPadding
	}
	unPadding := int(src[length-1])
	if length < unPadding {
		return src, ErrorUnPadding
	}
	return src[:(length - unPadding)], nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:18:57 ColeCai.
// ***********************************************************************************************
func PKCS5Padding(src []byte, blockSize int) []byte {
	return PKCS7Padding(src, blockSize)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:24:40 ColeCai.
// ***********************************************************************************************
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return PKCS7UnPadding(src)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:26:36 ColeCai.
// ***********************************************************************************************
func ZerosPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	if padding == 0 {
		return src
	}
	return append(src, bytes.Repeat([]byte{byte(0)}, padding)...)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:28:31 ColeCai.
// ***********************************************************************************************
func ZerosUnPadding(src []byte) ([]byte, error) {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1], nil
		}
	}
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:31:43 ColeCai.
// ***********************************************************************************************
func Padding(padding PaddingT, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		return PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		return PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		return ZerosPadding(src, blockSize)
	}
	return src
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/16 14:33:24 ColeCai.
// ***********************************************************************************************
func UnPadding(padding PaddingT, src []byte) ([]byte, error) {
	switch padding {
	case PKCS5_PADDING:
		return PKCS5UnPadding(src)
	case PKCS7_PADDING:
		return PKCS7UnPadding(src)
	case ZEROS_PADDING:
		return ZerosUnPadding(src)
	}
	return src, nil
}
