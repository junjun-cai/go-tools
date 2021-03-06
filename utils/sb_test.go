// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/13 18:25:38
// * File: utils.go
// * Proj: go-tools
// * Pack: utils
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
package utils

import "testing"

//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkB2S-12         1000000000               0.2525 ns/op          0 B/op          0 allocs/op
func BenchmarkB2S(b *testing.B) {
	bs := []byte("this is b2s benchmark")
	for i := 0; i < b.N; i++ {
		B2S(bs)
	}
}

//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkS2B-12         1000000000               0.2520 ns/op          0 B/op          0 allocs/op
func BenchmarkS2B(b *testing.B) {
	s := "this is b2s benchmark"
	for i := 0; i < b.N; i++ {
		S2B(s)
	}
}
