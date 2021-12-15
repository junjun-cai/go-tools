// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/14 10:48:14
// * File: utils.go
// * Proj: go-tools
// * Pack: utils
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package utils

import "math/rand"

const (
	stdStr      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	stdLen      = len(stdStr)
	stdStrUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	stdStrLower = "abcdefghijklmnopqrstuvwxyz"
	stdStrNum   = "0123456789"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	- before call this func must set rand seed.
// * HISTORY:
// *    -create: 2021/12/15 10:20:44 ColeCai.
// ***********************************************************************************************
func RandStr(l int) string {
	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = stdStr[rand.Intn(stdLen)]
	}
	return B2S(result)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	- before call this func must set rand seed.
// * HISTORY:
// *    -create: 2021/12/15 10:28:52 ColeCai.
// ***********************************************************************************************
func RandStrByStr(str string, l int) string {
	cnt := len(str)
	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = str[rand.Intn(cnt)]
	}
	return B2S(result)
}
