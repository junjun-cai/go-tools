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
