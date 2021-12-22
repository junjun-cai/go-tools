// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/15 14:28:14
// * File: aes_test.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
package crypto

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"strings"
	"testing"
)

var (
	AesKey128 = []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}

	AesKey192 = []byte{
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
	}

	AesKey256 = []byte{
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
	}
)

var AesCBCTests = []struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	{
		"CBC-AES128",
		AesKey128,
		[]byte("this is aes cbc mode encrypt, aes key is 128 bits"),
		[]byte{
			0x41, 0x90, 0xd4, 0xcc, 0x19, 0x99, 0x9d, 0xea, 0x50, 0xb5, 0xf0, 0xd2, 0x01,
			0xf4, 0x14, 0xe4, 0x99, 0x54, 0xf5, 0x2c, 0x86, 0x80, 0x93, 0x53, 0x8f, 0x71,
			0x0e, 0xa5, 0x81, 0xd7, 0xb8, 0xaf, 0xb6, 0xac, 0x11, 0x8e, 0x9b, 0xbb, 0x4d,
			0xe1, 0x69, 0x9e, 0x13, 0x90, 0x97, 0x42, 0xae, 0xab, 0x0d, 0x16, 0x4f, 0xfa,
			0x32, 0x4b, 0x0c, 0x1d, 0xd3, 0x37, 0x81, 0x01, 0x6a, 0xb3, 0x09, 0x2a},
		PKCS7_PADDING,
	},
	{
		"CBC-AES192",
		AesKey192,
		[]byte("this is aes cbc mode encrypt, aes key is 192 bits"),
		[]byte{
			0x64, 0x3b, 0x06, 0xbe, 0x77, 0xfb, 0x7f, 0xdd, 0xdb, 0x31, 0x5b, 0x9d, 0xb8,
			0xfe, 0x89, 0x01, 0xab, 0xf0, 0xef, 0xeb, 0xd1, 0x0b, 0x23, 0x63, 0x58, 0xf7,
			0x9a, 0x9f, 0xfc, 0x44, 0x46, 0xb1, 0x2b, 0x51, 0xff, 0xeb, 0x2f, 0xde, 0x0a,
			0x2c, 0x09, 0xe2, 0xcb, 0xed, 0x01, 0x89, 0x18, 0x43, 0x9b, 0x8b, 0x0e, 0xc0,
			0xb9, 0x8d, 0x84, 0x4c, 0x56, 0xc3, 0x22, 0x77, 0x90, 0x5e, 0xaf, 0x01},
		PKCS7_PADDING,
	},
	{
		"CBC-AES256",
		AesKey256,
		[]byte("this is aes cbc mode encrypt, aes key is 256 bits"),
		[]byte{
			0x50, 0x65, 0xe6, 0xe0, 0xf4, 0x30, 0x6c, 0x75, 0x45, 0xae, 0x92, 0x54, 0x64,
			0xf4, 0x60, 0xa4, 0x9a, 0x07, 0xed, 0x3d, 0xbe, 0xd7, 0x9d, 0x01, 0xf6, 0x98,
			0x0f, 0xf3, 0x5a, 0x41, 0x3b, 0x93, 0x5c, 0xbc, 0xcc, 0x09, 0xbd, 0xd8, 0x9a,
			0x1a, 0x0c, 0xe0, 0xda, 0xc7, 0x4c, 0x8d, 0x6c, 0x08, 0x98, 0x57, 0x64, 0xbd,
			0xf2, 0x87, 0xa9, 0xb0, 0x0a, 0x5a, 0x7c, 0x73, 0xa9, 0x15, 0x55, 0xd4},
		PKCS7_PADDING,
	},
}

func TestAesCBCEncrypt(t *testing.T) {
	for _, test := range AesCBCTests {
		data, err := AesCBCEncrypt(test.in, test.key, test.key[:aes.BlockSize], test.pad)
		if err != nil {
			t.Errorf("%s AesCBCEncrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(data, test.out) {
			t.Errorf("%s: AesCBCEncrypt\nhave: %x\nwant: %x", test.name, data, test.out)
			continue
		}
		t.Logf("%s: AesCBCEncrypt\nhave: %x\nwant: %x", test.name, data, test.out)
	}
}

func TestAesCBCDecrypt(t *testing.T) {
	for _, test := range AesCBCTests {
		data, err := AesCBCDecrypt(test.out, test.key, test.key[:aes.BlockSize], test.pad)
		if err != nil {
			t.Errorf("%s AesCBCDecrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(data, test.in) {
			t.Errorf("%s: AesCBCDecrypt\nhave: %x\nwant: %x", test.name, data, test.in)
			continue
		}
		t.Logf("%s: AesCBCDecrypt\nhave: %s\nwant: %s", test.name, data, test.in)
	}
}

//$ go test -bench=BenchmarkAesCBCEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCBCEncrypt-12        2173509               531.7 ns/op           752 B/op         10 allocs/op
//BenchmarkAesCBCEncrypt-12        2234392               531.2 ns/op           752 B/op         10 allocs/op
//BenchmarkAesCBCEncrypt-12        2227069               536.7 ns/op           752 B/op         10 allocs/op
func BenchmarkAesCBCEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCBCEncrypt(AesCBCTests[0].in, AesCBCTests[0].key, AesCBCTests[0].key[:aes.BlockSize], AesCBCTests[0].pad)
	}
}

//$ go test -bench=BenchmarkAesCBCDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCBCDecrypt-12        2737118               433.9 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCBCDecrypt-12        2784050               431.0 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCBCDecrypt-12        2774395               434.3 ns/op           624 B/op          8 allocs/op
func BenchmarkAesCBCDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCBCDecrypt(AesCBCTests[0].out, AesCBCTests[0].key, AesCBCTests[0].key[:aes.BlockSize], AesCBCTests[0].pad)
	}
}

var AesECBTests = []struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	{
		"ECB-AES128",
		AesKey128,
		[]byte("this is aes ecb mode encrypt, aes key is 128 bits"),
		[]byte{
			0xb0, 0x7b, 0xbc, 0x88, 0x2f, 0x14, 0x16, 0x99, 0x31, 0xce, 0xd6, 0x25, 0x6a,
			0xea, 0xc9, 0x99, 0xfd, 0x56, 0xeb, 0x5b, 0x70, 0x98, 0x74, 0xf2, 0x6e, 0x62,
			0x3f, 0xbb, 0x1f, 0x87, 0x65, 0xd8, 0xa0, 0xb4, 0x03, 0x17, 0x66, 0x8a, 0xb1,
			0x94, 0xf6, 0x6e, 0xaa, 0x9b, 0x8c, 0x2c, 0xfd, 0x0c, 0x1c, 0xd5, 0x16, 0xb6,
			0xa1, 0xdd, 0x26, 0x86, 0x88, 0x12, 0x95, 0x05, 0x80, 0x18, 0x17, 0x47},
		PKCS7_PADDING,
	},
	{
		"ECB-AES192",
		AesKey192,
		[]byte("this is aes ecb mode encrypt, aes key is 192 bits"),
		[]byte{
			0xa6, 0xd7, 0x93, 0xfb, 0x0a, 0x1f, 0x99, 0xe7, 0x0d, 0xdc, 0x9b, 0x64, 0xd8,
			0x43, 0xed, 0xab, 0xcc, 0xae, 0x7b, 0x58, 0xfe, 0x69, 0x77, 0xa5, 0xc6, 0x85,
			0xcc, 0x46, 0xb6, 0x04, 0x5c, 0x8f, 0xc4, 0xbd, 0xa6, 0x70, 0x9e, 0x10, 0xf8,
			0x4b, 0xd7, 0xee, 0x18, 0x8d, 0xcb, 0xf2, 0x04, 0x36, 0xdc, 0x3c, 0x2d, 0xd8,
			0xb5, 0xdd, 0x9b, 0x0f, 0xc3, 0xae, 0x7e, 0xaa, 0x92, 0x12, 0xde, 0x00},
		PKCS7_PADDING,
	},
	{
		"ECB-AES256",
		AesKey256,
		[]byte("this is aes ecb mode encrypt, aes key is 256 bits"),
		[]byte{
			0x8e, 0x8c, 0xf6, 0x7d, 0x59, 0x66, 0xf6, 0xbf, 0xb1, 0x92, 0xc3, 0x9d, 0xaa,
			0xe0, 0x2c, 0x6b, 0xe7, 0x19, 0x6d, 0xf9, 0xc4, 0xfb, 0x9d, 0xd6, 0x3f, 0x6a,
			0x9f, 0x78, 0xed, 0x97, 0xea, 0x34, 0xfb, 0x21, 0xa7, 0x33, 0xba, 0x30, 0x43,
			0x18, 0xc4, 0x05, 0x7a, 0x0a, 0x8b, 0x7d, 0x30, 0xd8, 0x1e, 0x6a, 0xa5, 0xa4,
			0xac, 0x90, 0xc4, 0xf0, 0xc3, 0xc2, 0x2e, 0x5b, 0xab, 0x53, 0x50, 0x05},
		PKCS7_PADDING,
	},
}

func TestAesECBEncrypt(t *testing.T) {
	for _, test := range AesECBTests {
		data, err := AesECBEncrypt(test.in, test.key, test.pad)
		if err != nil {
			t.Errorf("%s AesECBEncrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(data, test.out) {
			t.Errorf("%s: AesECBEncrypt\nhave: %x\nwant: %x", test.name, data, test.out)
			continue
		}
		t.Logf("%s: AesECBEncrypt\nhave: %x\nwant: %x", test.name, data, test.out)
	}
}

func TestAesECBDecrypt(t *testing.T) {
	for _, test := range AesECBTests {
		data, err := AesECBDecrypt(test.out, test.key, PKCS7_PADDING)
		if err != nil {
			t.Errorf("%s AesECBDecrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(data, test.in) {
			t.Errorf("%s: AesECBDecrypt\nhave: %x\nwant: %x", test.name, data, test.in)
			continue
		}
		t.Logf("%s: AesECBDecrypt\nhave: %s\nwant: %s", test.name, data, test.in)
	}
}

//$ go test -bench=BenchmarkAesECBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesECBEncrypt-12        2978385               396.0 ns/op           640 B/op          7 allocs/op
//BenchmarkAesECBEncrypt-12        3063946               390.4 ns/op           640 B/op          7 allocs/op
//BenchmarkAesECBEncrypt-12        3057181               388.5 ns/op           640 B/op          7 allocs/op
func BenchmarkAesECBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesECBEncrypt(AesECBTests[0].in, AesECBTests[0].key, AesECBTests[0].pad)
	}
}

//$ go test -bench=BenchmarkAesECBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesECBDecrypt-12        4198688               285.8 ns/op           512 B/op          5 allocs/op
//BenchmarkAesECBDecrypt-12        4198124               283.8 ns/op           512 B/op          5 allocs/op
//BenchmarkAesECBDecrypt-12        4211775               286.2 ns/op           512 B/op          5 allocs/op
func BenchmarkAesECBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesECBDecrypt(AesECBTests[0].out, AesECBTests[0].key, AesECBTests[0].pad)
	}
}

var AesCFBTests = []struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	{
		"CFB-AES128",
		AesKey128,
		[]byte("this is aes cfb mode encrypt, aes key is 128 bits"),
		[]byte{
			0x0b, 0x5d, 0xf8, 0xa0, 0x4f, 0xbc, 0x64, 0x83, 0x1a, 0x08, 0x9a, 0xc0, 0xbc,
			0xf5, 0x29, 0x5a, 0x7e, 0x60, 0xbb, 0x24, 0x2b, 0x31, 0x82, 0x0c, 0x59, 0x49,
			0x66, 0x18, 0x3b, 0x2c, 0x14, 0xd7, 0x8b, 0x39, 0x17, 0x0c, 0xb7, 0xfb, 0xf9,
			0x75, 0xbf, 0x4d, 0x52, 0xfd, 0x6d, 0x7a, 0xca, 0x7e, 0x76},
		PKCS7_PADDING,
	},
	{
		"CFB-AES192",
		AesKey192,
		[]byte("this is aes cfb mode encrypt, aes key is 192 bits"),
		[]byte{
			0x9e, 0x05, 0x97, 0x2a, 0xb3, 0x75, 0xd3, 0x78, 0x83, 0xbe, 0x95, 0x9c, 0x82,
			0x3e, 0x68, 0xbd, 0x3f, 0x8f, 0x1a, 0xdd, 0x1a, 0x4d, 0xb2, 0x3d, 0x91, 0xbd,
			0x15, 0x6e, 0x00, 0xc1, 0x2d, 0x0e, 0x37, 0xb3, 0xe4, 0x8b, 0x29, 0xe5, 0xcf,
			0x3b, 0x43, 0xec, 0x48, 0x04, 0x2f, 0xa2, 0xb3, 0x8f, 0xe8},
		PKCS7_PADDING,
	},
	{
		"CFB-AES256",
		AesKey256,
		[]byte("this is aes cfb mode encrypt, aes key is 256 bits"),
		[]byte{
			0x19, 0xd5, 0x4d, 0x26, 0xaa, 0x7b, 0x2d, 0xe6, 0x7b, 0x99, 0x31, 0x24, 0xe1,
			0xa7, 0x5b, 0x06, 0xae, 0x7e, 0xc9, 0xe5, 0x02, 0xbd, 0xed, 0x3f, 0xd7, 0x56,
			0x76, 0xf0, 0x0b, 0x81, 0xc0, 0xb9, 0x61, 0x3c, 0xc4, 0x86, 0xe8, 0xf7, 0x68,
			0x57, 0x80, 0x22, 0xee, 0xa8, 0xcb, 0x92, 0xcd, 0x5d, 0x71},
		PKCS7_PADDING,
	},
}

func TestAesCFBEncrypt(t *testing.T) {
	for _, test := range AesCFBTests {
		encrypted, err := AesCFBEncrypt(test.in, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesCFBEncrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(encrypted, test.out) {
			t.Errorf("%s: AesCFBEncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
			continue
		}
		t.Logf("%s: AesCFBEncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
	}
}

func TestAesCFBDecrypt(t *testing.T) {
	for _, test := range AesCFBTests {
		decrypted, err := AesCFBDecrypt(test.out, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesCFBDecrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(decrypted, test.in) {
			t.Errorf("%s: AesCFBDecrypt\nhave: %x\nwant: %x", test.name, decrypted, test.in)
			continue
		}
		t.Logf("%s: AesCFBDecrypt\nhave: %s\nwant: %s", test.name, decrypted, test.in)
	}
}

//$ go test -bench=BenchmarkAesCFBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCFBEncrypt-12        2807554               422.4 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCFBEncrypt-12        2827762               419.9 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCFBEncrypt-12        2847835               420.4 ns/op           624 B/op          8 allocs/op
func BenchmarkAesCFBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCFBEncrypt(AesCFBTests[0].in, AesCFBTests[0].key, AesCFBTests[0].key[0:aes.BlockSize])
	}
}

//$ go test -bench=BenchmarkAesCFBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCFBDecrypt-12        2880738               465.5 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCFBDecrypt-12        2913422               412.9 ns/op           624 B/op          8 allocs/op
//BenchmarkAesCFBDecrypt-12        2929605               411.0 ns/op           624 B/op          8 allocs/op
func BenchmarkAesCFBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCFBDecrypt(AesCFBTests[0].out, AesCFBTests[0].key, AesCFBTests[0].key[0:aes.BlockSize])
	}
}

func FormatBytes(b []byte) {
	var strs []string
	for _, v := range b {
		strs = append(strs, fmt.Sprintf("0x%02x", v))
	}
	fmt.Println("S:", strings.Join(strs, ","))
}

var AesOFBTests = []struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	{
		"OFB-AES128",
		AesKey128,
		[]byte("this is aes ofb mode encrypt, aes key is 128 bits"),
		[]byte{
			0x0b, 0x5d, 0xf8, 0xa0, 0x4f, 0xbc, 0x64, 0x83, 0x1a, 0x08, 0x9a, 0xc0, 0xb0,
			0xf5, 0x29, 0x5a, 0x69, 0xa0, 0x20, 0xba, 0xc2, 0xa2, 0x58, 0x92, 0x5b, 0x10,
			0xd2, 0x16, 0x4f, 0xe4, 0x2d, 0xb3, 0x4c, 0x24, 0x65, 0x2f, 0x98, 0x5a, 0x59,
			0x54, 0x6a, 0x60, 0x94, 0x1a, 0x9d, 0xa0, 0xca, 0x60, 0x91},
		PKCS7_PADDING,
	},
	{
		"OFB-AES192",
		AesKey192,
		[]byte("this is aes ofb mode encrypt, aes key is 192 bits"),
		[]byte{
			0x9e, 0x05, 0x97, 0x2a, 0xb3, 0x75, 0xd3, 0x78, 0x83, 0xbe, 0x95, 0x9c, 0x8e,
			0x3e, 0x68, 0xbd, 0x26, 0xe1, 0xdc, 0xd8, 0x21, 0x66, 0x6a, 0x35, 0x9e, 0xfd,
			0x2d, 0xd0, 0xa6, 0x50, 0xf2, 0x3c, 0x03, 0x9b, 0xfe, 0x53, 0xf1, 0x1e, 0x34,
			0x12, 0xaa, 0x56, 0x86, 0xee, 0xa5, 0xf1, 0xe7, 0x44, 0xf4},
		PKCS7_PADDING,
	},
	{
		"OFB-AES256",
		AesKey256,
		[]byte("this is aes ofb mode encrypt, aes key is 256 bits"),
		[]byte{
			0x19, 0xd5, 0x4d, 0x26, 0xaa, 0x7b, 0x2d, 0xe6, 0x7b, 0x99, 0x31, 0x24, 0xed,
			0xa7, 0x5b, 0x06, 0xe7, 0xb9, 0x0c, 0xbb, 0x95, 0xc7, 0xc8, 0x73, 0xfa, 0xb6,
			0xfa, 0x3d, 0xb5, 0xf1, 0xf3, 0x67, 0xf6, 0xb0, 0xd2, 0x44, 0x88, 0x2c, 0x62,
			0x1a, 0x07, 0xf4, 0x6e, 0x6c, 0x59, 0x68, 0x72, 0xfa, 0xca},
		PKCS7_PADDING,
	},
}

func TestAesOFBEncrypt(t *testing.T) {
	for _, test := range AesOFBTests {
		encrypted, err := AesOFBEncrypt(test.in, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesOFBEncrypt failed,err:%+v", test.name, err)
			continue
		}

		if !bytes.Equal(encrypted, test.out) {
			t.Errorf("%s: AesOFBEncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
			continue
		}
		t.Logf("%s: AesOFBEncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
	}
}

func TestAesOFBDecrypt(t *testing.T) {
	for _, test := range AesOFBTests {
		decrypted, err := AesOFBDecrypt(test.out, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesOFBDecrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(decrypted, test.in) {
			t.Errorf("%s: AesOFBDecrypt\nhave: %x\nwant: %x", test.name, decrypted, test.in)
			continue
		}
		t.Logf("%s: AesOFBDecrypt\nhave: %s\nwant: %s", test.name, decrypted, test.in)
	}
}

//$ go test -bench=BenchmarkAesOFBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesOFBEncrypt-12        1478208               832.2 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesOFBEncrypt-12        1463552               814.0 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesOFBEncrypt-12        1491537               803.2 ns/op          1120 B/op          8 allocs/op
func BenchmarkAesOFBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesOFBEncrypt(AesOFBTests[0].in, AesOFBTests[0].key, AesOFBTests[0].key[0:aes.BlockSize])
	}
}

//$ go test -bench=BenchmarkAesOFBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesOFBDecrypt-12        1472134               808.5 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesOFBDecrypt-12        1496898               803.1 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesOFBDecrypt-12        1475503               809.8 ns/op          1120 B/op          8 allocs/op
func BenchmarkAesOFBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesOFBDecrypt(AesOFBTests[0].out, AesOFBTests[0].key, AesOFBTests[0].key[0:aes.BlockSize])
	}
}

var AesCTRTests = []struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	{
		"CTR-AES128",
		AesKey128,
		[]byte("this is aes ctr mode encrypt, aes key is 128 bits"),
		[]byte{
			0x0b, 0x5d, 0xf8, 0xa0, 0x4f, 0xbc, 0x64, 0x83, 0x1a, 0x08, 0x9a, 0xc0, 0xbc,
			0xe7, 0x39, 0x5a, 0x4b, 0x89, 0xc5, 0x17, 0x2c, 0x3c, 0x8d, 0xf4, 0xd4, 0x1e,
			0x83, 0x8b, 0xd0, 0x30, 0xdb, 0xe0, 0xc9, 0xb1, 0xf3, 0xee, 0x59, 0x20, 0x45,
			0x77, 0xf7, 0xc0, 0x7c, 0x87, 0xb2, 0x5f, 0x3a, 0x7e, 0x06},
		PKCS7_PADDING,
	},
	{
		"CTR-AES192",
		AesKey192,
		[]byte("this is aes ctr mode encrypt, aes key is 192 bits"),
		[]byte{
			0x9e, 0x05, 0x97, 0x2a, 0xb3, 0x75, 0xd3, 0x78, 0x83, 0xbe, 0x95, 0x9c, 0x82,
			0x2c, 0x78, 0xbd, 0x6d, 0x65, 0x04, 0x21, 0xaf, 0x9c, 0xa5, 0xb2, 0xd3, 0x1a,
			0x28, 0x6a, 0x6a, 0x70, 0x58, 0xda, 0xfb, 0x51, 0x5b, 0xa4, 0x53, 0xf9, 0x32,
			0x2f, 0x49, 0xca, 0x69, 0x59, 0x7d, 0xae, 0x0d, 0x3d, 0x48,
		},
		PKCS7_PADDING,
	},
	{
		"CTR-AES256",
		AesKey256,
		[]byte("this is aes ctr mode encrypt, aes key is 256 bits"),
		[]byte{
			0x19, 0xd5, 0x4d, 0x26, 0xaa, 0x7b, 0x2d, 0xe6, 0x7b, 0x99, 0x31, 0x24, 0xe1,
			0xb5, 0x4b, 0x06, 0xc4, 0x70, 0xe0, 0x3c, 0x2d, 0x45, 0xa7, 0xce, 0x1a, 0xd0,
			0x7c, 0xf6, 0xa8, 0xff, 0xdc, 0x87, 0x14, 0x21, 0xb7, 0xfe, 0x71, 0x54, 0x6f,
			0x42, 0x34, 0x03, 0x14, 0x02, 0x16, 0x5d, 0xdd, 0x1f, 0x0c},
		PKCS7_PADDING,
	},
}

func TestAesCTREncrypt(t *testing.T) {
	for _, test := range AesCTRTests {
		encrypted, err := AesCTREncrypt(test.in, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesCTREncrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(encrypted, test.out) {
			t.Errorf("%s: AesCTREncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
			continue
		}
		t.Logf("%s: AesCTREncrypt\nhave: %x\nwant: %x", test.name, encrypted, test.out)
	}
}

func TestAesCTRDecrypt(t *testing.T) {
	for _, test := range AesCTRTests {
		decrypted, err := AesCTRDecrypt(test.out, test.key, test.key[0:aes.BlockSize])
		if err != nil {
			t.Errorf("%s AesCTRDecrypt failed,err:%+v", test.name, err)
			continue
		}
		if !bytes.Equal(decrypted, test.in) {
			t.Errorf("%s: AesCTRDecrypt\nhave: %x\nwant: %x", test.name, decrypted, test.in)
			continue
		}
		t.Logf("%s: AesCTRDecrypt\nhave: %s\nwant: %s", test.name, decrypted, test.in)
	}
}

//$ go test -bench=BenchmarkAesCTREncrypt --benchmem --count=3
//goos: windows
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCTREncrypt-12        1267471               949.4 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesCTREncrypt-12        1258188               945.7 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesCTREncrypt-12        1274462               942.5 ns/op          1120 B/op          8 allocs/op
func BenchmarkAesCTREncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCTREncrypt(AesCTRTests[0].in, AesCTRTests[0].key, AesCTRTests[0].key[0:aes.BlockSize])
	}
}

//$ go test -bench=BenchmarkAesCTRDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkAesCTRDecrypt-12        1268498               948.5 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesCTRDecrypt-12        1249602               946.4 ns/op          1120 B/op          8 allocs/op
//BenchmarkAesCTRDecrypt-12        1268564               944.8 ns/op          1120 B/op          8 allocs/op
func BenchmarkAesCTRDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = AesCTRDecrypt(AesCTRTests[0].out, AesCTRTests[0].key, AesCTRTests[0].key[0:aes.BlockSize])
	}
}
