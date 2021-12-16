// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/15 10:15:14
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
	StdStr      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	StdLen      = len(StdStr)
	StdStrUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	StdStrLower = "abcdefghijklmnopqrstuvwxyz"
	StdStrNum   = "0123456789"
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
		result[i] = StdStr[rand.Intn(StdLen)]
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

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	- capability will drop with str length add.
// * HISTORY:
// *    -create: 2021/12/15 11:31:02 ColeCai.
// ***********************************************************************************************
func BKDRHash(str string) int {
	seed := 13131 // 31 131 1313 13131 131313 etc..
	hash := 0
	for _, ch := range str {
		hash = hash*seed + int(ch)
	}
	return hash & 0x7FFFFFFF
}
