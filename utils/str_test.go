// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/15 10:22:57
// * File: utils.go
// * Proj: go-tools
// * Pack: utils
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
package utils

import "testing"

//go test -bench=BenchmarkRandStr -benchmem
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkRandString-12           6253761               190.5 ns/op            16 B/op          1 allocs/op
func BenchmarkRandString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RandStr(10)
	}
}

//go test -bench=BenchmarkRandStrByStr -benchmem
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkRandStringByString-12           5976949               198.2 ns/op            16 B/op          1 allocs/op
func BenchmarkRandStringByString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RandStrByStr(stdStr, 10)
	}
}
