// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/01/19 09:32:45
// * File: rsa_test.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

type Writer struct {
	b []byte
}

func (w *Writer) Write(b []byte) (int, error) {
	w.b = append(w.b, b...)
	return len(b), nil
}

func (w *Writer) Fmt() {
	fmt.Println(string(w.b))
}

func TestGenRsaKey(t *testing.T) {
	pri := &Writer{}
	pub := &Writer{}
	GenRsaKey(pri, pub, 256)
}

var RsaTests = struct {
	name   string
	pubKey []byte
	priKey []byte
	in     []byte
	out    []byte
}{
	"RSA",
	[]byte(
		`-----BEGIN RSA PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALOB9CovvPpGsLMWKbeW9yBhUdUCsAgH
wjBgbtjdHF03AgMBAAE=
-----END RSA PUBLIC KEY-----`),
	[]byte(
		`-----BEGIN RSA PRIVATE KEY-----
MIGqAgEAAiEAs4H0Ki+8+kawsxYpt5b3IGFR1QKwCAfCMGBu2N0cXTcCAwEAAQIg
Z2uRvtRuLkuX9jXopwtlKN1TcuurM3gf8rP1EF8o3UECEQDhk+GpP5GPwfYTdSUP
EKBHAhEAy7d+jJZCrIlT452PRclDkQIQMvgPDQboBOt2hn75mKXREQIRAKwYQ2v4
tDKVgKzUueg2ckECEFfP/N5RfFPTgcH2IzbfsRM=
-----END RSA PRIVATE KEY-----`),
	[]byte("this is rsa crypto"),
	[]byte{
		0x78, 0x44, 0xa5, 0xfa, 0xa0, 0xd9, 0xb8, 0xbc, 0xb5, 0xeb, 0xaa, 0x13, 0xd8, 0xb1,
		0x2a, 0x69, 0x43, 0x7c, 0x45, 0xcd, 0x9b, 0x8d, 0x9f, 0xf5, 0x99, 0x3f, 0xae, 0xc0,
		0x25, 0xfc, 0xb0, 0x64},
}

func TestRsaCrypto(t *testing.T) {
	encrypted, err := RsaEncrypt(RsaTests.in, RsaTests.pubKey)
	if err != nil {
		t.Errorf("%s RsaEncrypt failed,err:%+v", RsaTests.name, err)
		return
	}
	decrypted, err := RsaDecrypt(encrypted, RsaTests.priKey)
	if err != nil {
		t.Errorf("%s RsaEncrypt failed,err:%+v", RsaTests.name, err)
		return
	}
	if !bytes.Equal(decrypted, RsaTests.in) {
		t.Errorf("%s: RsaEncrypt\nhave: %x\nwant: %x", RsaTests.name, decrypted, RsaTests.in)
		return
	}
	t.Logf("%s: RsaEncrypt\nhave: %x\nwant: %x", RsaTests.name, decrypted, RsaTests.in)
}

//$ go test -bench=BenchmarkRsaEncrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkRsaEncrypt-12            149089              8050 ns/op            1460 B/op         39 allocs/op
//BenchmarkRsaEncrypt-12            149024              8035 ns/op            1460 B/op         39 allocs/op
//BenchmarkRsaEncrypt-12            148695              8068 ns/op            1460 B/op         39 allocs/op
func BenchmarkRsaEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = RsaEncrypt(RsaTests.in, RsaTests.pubKey)
	}
}

//$ go test -bench=BenchmarkRsaDecrypt --benchmem --count=3
//goos: windows
//goarch: amd64
//cpu: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz
//BenchmarkRsaDecrypt-12             34398             34638 ns/op            8016 B/op        169 allocs/op
//BenchmarkRsaDecrypt-12             34779             34537 ns/op            8016 B/op        169 allocs/op
//BenchmarkRsaDecrypt-12             34644             34451 ns/op            8016 B/op        169 allocs/op
func BenchmarkRsaDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = RsaDecrypt(RsaTests.out, RsaTests.priKey)
	}
}
