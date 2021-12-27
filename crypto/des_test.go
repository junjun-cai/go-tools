//*********************************************************************************
//@Auth:蔡君君
//@Date:2021/12/23 11:42
//@File:des_test.go
//@Pack:crypto
//@Proj:go-tools
//@Ides:GoLand
//@Desc:
//*********************************************************************************

package crypto

import (
	"bytes"
	"testing"
)

var (
	DesKey8 = []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	}
)

var DesCBCTests = struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"CBC-DES8",
	DesKey8,
	[]byte("this is des cbc mode encrypt, aes key is 64 bits"),
	[]byte{
		0x47, 0x5f, 0x25, 0xb5, 0xfd, 0xbf, 0xd3, 0x30, 0x81, 0x2e, 0xae, 0x95, 0x12, 0xbf,
		0x96, 0x86, 0x52, 0x67, 0xc7, 0xbb, 0xd8, 0x78, 0x64, 0x0f, 0x6a, 0x3f, 0x35, 0x22,
		0xd3, 0x3b, 0x8a, 0xe8, 0x37, 0x5a, 0x9c, 0x15, 0xe1, 0xb0, 0x24, 0xac, 0x45, 0x5d,
		0xb0, 0x58, 0x3b, 0xd8, 0xb6, 0x2a, 0x4f, 0x41, 0xa3, 0x79, 0x7e, 0xca, 0x0e, 0xc4},
	PKCS7_PADDING,
}

func TestDesCBCEncrypt(t *testing.T) {
	encrypted, err := DesCBCEncrypt(DesCBCTests.in, DesCBCTests.key, DesCBCTests.key, DesCBCTests.pad)
	if err != nil {
		t.Errorf("%s DesCBCEncrypt failed,err:%+v", DesCBCTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, DesCBCTests.out) {
		t.Errorf("%s: DesCBCEncrypt\nhave: %x\nwant: %x", DesCBCTests.name, encrypted, DesCBCTests.out)
		return
	}
	t.Logf("%s: DesCBCEncrypt\nhave: %x\nwant: %x", DesCBCTests.name, encrypted, DesCBCTests.out)
}

func TestDesCBCDecrypt(t *testing.T) {
	decrypted, err := DesCBCDecrypt(DesCBCTests.out, DesCBCTests.key, DesCBCTests.key, DesCBCTests.pad)
	if err != nil {
		t.Errorf("%s DesCBCDecrypt failed,err:%+v", DesCBCTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, DesCBCTests.in) {
		t.Errorf("%s: DesCBCEncrypt\nhave: %x\nwant: %x", DesCBCTests.name, decrypted, DesCBCTests.in)
		return
	}
	t.Logf("%s: DesCBCEncrypt\nhave: %x\nwant: %x", DesCBCTests.name, decrypted, DesCBCTests.in)
}

//$ go test -bench=BenchmarkDesCBCEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDesCBCEncrypt-12         456044              2520 ns/op             392 B/op          7 allocs/op
//BenchmarkDesCBCEncrypt-12         499612              2459 ns/op             392 B/op          7 allocs/op
//BenchmarkDesCBCEncrypt-12         452570              2449 ns/op             392 B/op          7 allocs/op
func BenchmarkDesCBCEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesCBCEncrypt(DesCBCTests.in, DesCBCTests.key, DesCBCTests.key, DesCBCTests.pad)
	}
}

//$ go test -bench=BenchmarkDesCBCDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDesCBCDecrypt-12         512660              2359 ns/op             288 B/op          5 allocs/op
//BenchmarkDesCBCDecrypt-12         499620              2354 ns/op             288 B/op          5 allocs/op
//BenchmarkDesCBCDecrypt-12         508706              2351 ns/op             288 B/op          5 allocs/op
func BenchmarkDesCBCDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesCBCDecrypt(DesCBCTests.out, DesCBCTests.key, DesCBCTests.key, DesCBCTests.pad)
	}
}

var DesECBTests = struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"ECB-DES8",
	DesKey8,
	[]byte("this is des ecb mode encrypt, aes key is 64 bits"),
	[]byte{
		0xd9, 0xcd, 0x51, 0x00, 0x0d, 0xb6, 0x9d, 0x23, 0xea, 0xba, 0xd0, 0x6e, 0x4c, 0xbe,
		0x15, 0xab, 0x50, 0xbc, 0x76, 0x92, 0x61, 0xea, 0xcb, 0x31, 0xf6, 0x41, 0xea, 0x21,
		0x50, 0xd9, 0xb8, 0x96, 0x4f, 0xe6, 0xfb, 0x10, 0x1d, 0xbf, 0x9b, 0xf1, 0x23, 0x3e,
		0x25, 0x03, 0x01, 0x75, 0xcb, 0x63, 0x3d, 0x22, 0xd1, 0x3c, 0x3d, 0x4d, 0x5f, 0x1e},
	PKCS7_PADDING,
}

func TestDesECBEncrypt(t *testing.T) {
	encrypted, err := DesECBEncrypt(DesECBTests.in, DesECBTests.key, DesECBTests.pad)
	if err != nil {
		t.Errorf("%s DesECBEncrypt failed,err:%+v", DesECBTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, DesECBTests.out) {
		t.Errorf("%s: DesECBEncrypt\nhave: %x\nwant: %x", DesECBTests.name, encrypted, DesECBTests.out)
		return
	}
	t.Logf("%s: DesECBEncrypt\nhave: %x\nwant: %x", DesECBTests.name, encrypted, DesECBTests.out)
}

func TestDesECBDecrypt(t *testing.T) {
	decrypted, err := DesECBDecrypt(DesECBTests.out, DesECBTests.key, DesECBTests.pad)
	if err != nil {
		t.Errorf("%s DesECBDecrypt failed,err:%+v", DesECBTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, DesECBTests.in) {
		t.Errorf("%s: DesECBDecrypt\nhave: %x\nwant: %x", DesECBTests.name, decrypted, DesECBTests.in)
		return
	}
	t.Logf("%s: DesECBDecrypt\nhave: %x\nwant: %x", DesECBTests.name, decrypted, DesECBTests.in)
}

//$ go test -bench=BenchmarkDesECBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDesECBEncrypt-12         524476              2320 ns/op             296 B/op          4 allocs/op
//BenchmarkDesECBEncrypt-12         533138              2316 ns/op             296 B/op          4 allocs/op
//BenchmarkDesECBEncrypt-12         532263              2313 ns/op             296 B/op          4 allocs/op
func BenchmarkDesECBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesECBEncrypt(DesECBTests.in, DesECBTests.key, DesECBTests.pad)
	}
}

//$ go test -bench=BenchmarkDesECBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDesECBDecrypt-12         536494              2224 ns/op             192 B/op          2 allocs/op
//BenchmarkDesECBDecrypt-12         557988              2214 ns/op             192 B/op          2 allocs/op
//BenchmarkDesECBDecrypt-12         545134              2213 ns/op             192 B/op          2 allocs/op
func BenchmarkDesECBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesECBDecrypt(DesECBTests.out, DesECBTests.key, DesECBTests.pad)
	}
}

var DesCFBTests = struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"CFB-DES8",
	DesKey8,
	[]byte("this is des cfb mode encrypt, aes key is 64 bits"),
	[]byte{
		0x73, 0x44, 0xaa, 0x1c, 0x64, 0x5c, 0x18, 0x39, 0x95, 0x9b, 0x15, 0xb1, 0x31, 0x2d,
		0x34, 0x45, 0x6f, 0xc1, 0x95, 0xfb, 0xc2, 0xb7, 0x6f, 0x2c, 0x8f, 0xf0, 0xf9, 0xe6,
		0xd9, 0x8a, 0x62, 0xfa, 0x31, 0x51, 0x91, 0x14, 0x8a, 0xb4, 0x4b, 0x17, 0x41, 0xdd,
		0xf3, 0x3f, 0x39, 0xc2, 0x58, 0x72},
	PKCS7_PADDING,
}

func TestDesCFBEncrypt(t *testing.T) {
	encrypted, err := DesCFBEncrypt(DesCFBTests.in, DesCFBTests.key, DesCFBTests.key)
	if err != nil {
		t.Errorf("%s DesCFBEncrypt failed,err:%+v", DesCFBTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, DesCFBTests.out) {
		t.Errorf("%s: DesCFBEncrypt\nhave: %x\nwant: %x", DesCFBTests.name, encrypted, DesCFBTests.out)
		return
	}
	t.Logf("%s: DesCFBEncrypt\nhave: %x\nwant: %x", DesCFBTests.name, encrypted, DesCFBTests.out)
}

func TestDesCFBDecrypt(t *testing.T) {
	decrypted, err := DesCFBDecrypt(DesCFBTests.out, DesCFBTests.key, DesECBTests.key)
	if err != nil {
		t.Errorf("%s DesCFBDecrypt failed,err:%+v", DesCFBTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, DesCFBTests.in) {
		t.Errorf("%s: DesCFBDecrypt\nhave: %x\nwant: %x", DesCFBTests.name, decrypted, DesCFBTests.in)
		return
	}
	t.Logf("%s: DesCFBDecrypt\nhave: %x\nwant: %x", DesCFBTests.name, decrypted, DesCFBTests.in)
}

//$ go test -bench=BenchmarkDesCFBEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkDesCFBEncrypt-12         533830              2251 ns/op             272 B/op          5 allocs/op
//BenchmarkDesCFBEncrypt-12         533077              2265 ns/op             272 B/op          5 allocs/op
//BenchmarkDesCFBEncrypt-12         545481              2252 ns/op             272 B/op          5 allocs/op
func BenchmarkDesCFBEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesCFBEncrypt(DesCFBTests.in, DesCFBTests.key, DesCFBTests.key)
	}
}

//$ go test -bench=BenchmarkDesCFBDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//pkg: github.com/junjun-cai/go-tools/crypto
//BenchmarkDesCFBDecrypt-12         514030              2303 ns/op             272 B/op          5 allocs/op
//BenchmarkDesCFBDecrypt-12         555462              2244 ns/op             272 B/op          5 allocs/op
//BenchmarkDesCFBDecrypt-12         544720              2247 ns/op             272 B/op          5 allocs/op
func BenchmarkDesCFBDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DesCFBDecrypt(DesCFBTests.out, DesCFBTests.key, DesCFBTests.key)
	}
}

var DesOFBTests = struct {
	name string
	key  []byte
	in   []byte
	out  []byte
	pad  PaddingT
}{
	"OFB-DES8",
	DesKey8,
	[]byte("this is des ofb mode encrypt, aes key is 64 bits"),
	[]byte{
		0x73, 0x44, 0xaa, 0x1c, 0x64, 0x5c, 0x18, 0x39, 0x83, 0xe4, 0x8c, 0xff, 0xa8, 0x47,
		0x3e, 0xfb, 0xfc, 0x8d, 0x8e, 0xcc, 0x8e, 0xad, 0x34, 0x2c, 0x40, 0x4c, 0x66, 0x95,
		0x2c, 0x78, 0xb8, 0x1e, 0x32, 0xee, 0x98, 0xf6, 0xec, 0xf7, 0x07, 0x37, 0x6a, 0xe1,
		0xf6, 0x38, 0x42, 0x4d, 0xab, 0x1d},
	PKCS7_PADDING,
}

func TestDesOFBEncrypt(t *testing.T) {
	encrypted, err := DesOFBEncrypt(DesOFBTests.in, DesOFBTests.key, DesOFBTests.key)
	if err != nil {
		t.Errorf("%s DesOFBEncrypt failed,err:%+v", DesOFBTests.name, err)
		return
	}
	if !bytes.Equal(encrypted, DesOFBTests.out) {
		t.Errorf("%s: DesOFBEncrypt\nhave: %x\nwant: %x", DesOFBTests.name, encrypted, DesOFBTests.out)
		return
	}
	t.Logf("%s: DesOFBEncrypt\nhave: %x\nwant: %x", DesOFBTests.name, encrypted, DesOFBTests.out)
}

func TestDesOFBDecrypt(t *testing.T) {
	decrypted, err := DesOFBDecrypt(DesOFBTests.out, DesOFBTests.key, DesOFBTests.key)
	if err != nil {
		t.Errorf("%s DesOFBDecrypt failed,err:%+v", DesOFBTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, DesOFBTests.in) {
		t.Errorf("%s: DesOFBDecrypt\nhave: %x\nwant: %x", DesOFBTests.name, decrypted, DesOFBTests.in)
		return
	}
	t.Logf("%s: DesOFBDecrypt\nhave: %x\nwant: %x", DesOFBTests.name, decrypted, DesOFBTests.in)
}
