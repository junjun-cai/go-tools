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

import (
	"testing"
)

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
		RandStrByStr(StdStr, 10)
	}
}

//go test -bench=BenchmarkBKDRHash -benchmem
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkBKDRHash-12            26713266                45.58 ns/op            0 B/op          0 allocs/op
//ops will grow with str length add.
func BenchmarkBKDRHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		BKDRHash(StdStr)
	}
}

//go test -bench=BenchmarkReverseString -benchmem
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkReverseString-12        2747692               451.5 ns/op           256 B/op          2 allocs/op
//BenchmarkReverseString-12        2775624               432.6 ns/op           256 B/op          2 allocs/op
//BenchmarkReverseString-12        2763499               433.5 ns/op           256 B/op          2 allocs/op
func BenchmarkReverseString(b *testing.B) {
	s := "go test -bench=BenchmarkReverseString -benchmem"
	for i := 0; i < b.N; i++ {
		ReverseString(s)
	}
}
