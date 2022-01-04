// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/31 10:17:29
// * File: 3des_test.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"bytes"
	"testing"
)

var (
	Des3Key24 = []byte{
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
	}
	Des3IV8 = []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	}
)

var Des3CBCTests = struct {
	name string
	key  []byte
	iv   []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"CBC-3DES24",
	Des3Key24,
	Des3IV8,
	[]byte("this is 3des cbc mode encrypt, 3des key is 192 bits"),
	[]byte{
		0xb3, 0x9c, 0x35, 0x70, 0xc2, 0xa0, 0x1b, 0xaf, 0xec, 0x7b, 0x03, 0x21, 0x41, 0xa0,
		0x14, 0x2c, 0xdf, 0xea, 0x49, 0x39, 0xe0, 0x24, 0x9a, 0x2a, 0xff, 0xef, 0x9f, 0x87,
		0xc5, 0x70, 0x5f, 0x26, 0x28, 0xec, 0x38, 0x66, 0x9a, 0x88, 0xa2, 0x88, 0x56, 0x75,
		0x8d, 0xbd, 0x84, 0x1f, 0x77, 0x0d, 0x4d, 0xf9, 0xfa, 0x61, 0x3b, 0xb6, 0x3c, 0x53},
	PKCS7_PADDING,
}

func TestDes3CBCEncrypt(t *testing.T) {
	encrypted, err := Des3CBCEncrypt(Des3CBCTests.in, Des3CBCTests.key, Des3CBCTests.iv, Des3CBCTests.pad)
	if err != nil {
		t.Errorf("%s Des3CBCEncrypt failed,err:%+v", Des3CBCTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, Des3CBCTests.out) {
		t.Errorf("%s: Des3CBCEncrypt\nhave: %x\nwant: %x", Des3CBCTests.name, encrypted, Des3CBCTests.out)
		return
	}
	t.Logf("%s: Des3CBCEncrypt\nhave: %x\nwant: %x", Des3CBCTests.name, encrypted, Des3CBCTests.out)
}

func TestDes3CBCDecrypt(t *testing.T) {
	decrypted, err := Des3CBCDecrypt(Des3CBCTests.out, Des3CBCTests.key, Des3CBCTests.iv, Des3CBCTests.pad)
	if err != nil {
		t.Errorf("%s Des3CBCDecrypt failed,err:%+v", Des3CBCTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, Des3CBCTests.in) {
		t.Errorf("%s: Des3CBCDecrypt\nhave: %x\nwant: %x", Des3CBCTests.name, decrypted, Des3CBCTests.in)
		return
	}
	t.Logf("%s: Des3CBCDecrypt\nhave: %s\nwant: %s", Des3CBCTests.name, decrypted, Des3CBCTests.in)
}

//$ go test -bench=BenchmarkDes3CBCEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDes3CBCEncrypt-12        182310              6504 ns/op             664 B/op          7 allocs/op
//BenchmarkDes3CBCEncrypt-12        176114              6523 ns/op             664 B/op          7 allocs/op
//BenchmarkDes3CBCEncrypt-12        186967              6488 ns/op             664 B/op          7 allocs/op
func BenchmarkDes3CBCEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Des3CBCEncrypt(Des3CBCTests.in, Des3CBCTests.key, Des3CBCTests.iv, Des3CBCTests.pad)
	}
}

//$ go test -bench=BenchmarkDes3CBCDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDes3CBCDecrypt-12        185245              6352 ns/op             544 B/op          5 allocs/op
//BenchmarkDes3CBCDecrypt-12        189756              6354 ns/op             544 B/op          5 allocs/op
//BenchmarkDes3CBCDecrypt-12        188100              6400 ns/op             544 B/op          5 allocs/op
func BenchmarkDes3CBCDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Des3CBCDecrypt(Des3CBCTests.out, Des3CBCTests.key, Des3CBCTests.iv, Des3CBCTests.pad)
	}
}

var Des3ECBTests = struct {
	name string
	key  []byte
	iv   []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"ECB-3DES24",
	Des3Key24,
	Des3IV8,
	[]byte("this is 3des ecb mode encrypt, 3des key is 192 bits"),
	[]byte{
		0x36, 0x49, 0x93, 0xed, 0x5d, 0x68, 0x8b, 0xb6, 0x23, 0x65, 0x45, 0xf3, 0x97, 0x01,
		0xf1, 0x45, 0x4c, 0xba, 0x90, 0x6d, 0xa8, 0x47, 0x12, 0x4b, 0x39, 0x8a, 0x68, 0xa6,
		0x16, 0x92, 0x05, 0x73, 0xc7, 0x71, 0xe1, 0x67, 0x6e, 0xef, 0x3f, 0x5b, 0xbc, 0x29,
		0x6f, 0x3b, 0x49, 0xb7, 0x3a, 0x5e, 0x1e, 0x5d, 0x50, 0x31, 0x92, 0xeb, 0x42, 0x22},
	PKCS7_PADDING,
}

func TestDes3ECBEncrypt(t *testing.T) {
	encrypted, err := Des3ECBEncrypt(Des3ECBTests.in, Des3ECBTests.key, Des3ECBTests.pad)
	if err != nil {
		t.Errorf("%s Des3ECBEncrypt failed,err:%+v", Des3ECBTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, Des3ECBTests.out) {
		t.Errorf("%s: Des3ECBEncrypt\nhave: %x\nwant: %x", Des3ECBTests.name, encrypted, Des3ECBTests.out)
		return
	}
	t.Logf("%s: Des3CBCEncrypt\nhave: %x\nwant: %x", Des3ECBTests.name, encrypted, Des3ECBTests.out)
}

func TestDes3ECBDecrypt(t *testing.T) {
	decrypted, err := Des3ECBDecrypt(Des3ECBTests.out, Des3ECBTests.key, Des3ECBTests.pad)
	if err != nil {
		t.Errorf("%s Des3ECBDecrypt failed,err:%+v", Des3ECBTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, Des3ECBTests.in) {
		t.Errorf("%s: Des3ECBDecrypt\nhave: %x\nwant: %x", Des3ECBTests.name, decrypted, Des3ECBTests.in)
		return
	}
	t.Logf("%s: Des3ECBDecrypt\nhave: %s\nwant: %s", Des3ECBTests.name, decrypted, Des3ECBTests.in)
}

//$ go test -bench=BenchmarkDes3ECBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDes3ECBEncrypt-12        189634              6293 ns/op             565 B/op          4 allocs/op
//BenchmarkDes3ECBEncrypt-12        192286              6249 ns/op             565 B/op          4 allocs/op
//BenchmarkDes3ECBEncrypt-12        191206              6327 ns/op             565 B/op          4 allocs/op
func BenchmarkDes3ECBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Des3ECBEncrypt(Des3ECBTests.in, Des3ECBTests.key, Des3ECBTests.pad)
	}
}

//$ go test -bench=BenchmarkDes3ECBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDes3ECBDecrypt-12        191202              6171 ns/op             448 B/op          2 allocs/op
//BenchmarkDes3ECBDecrypt-12        193642              6174 ns/op             448 B/op          2 allocs/op
//BenchmarkDes3ECBDecrypt-12        191647              6170 ns/op             448 B/op          2 allocs/op
func BenchmarkDes3ECBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Des3ECBDecrypt(Des3ECBTests.out, Des3ECBTests.key, Des3ECBTests.pad)
	}
}
