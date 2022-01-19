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
	pri.Fmt()

	pub.Fmt()
}

var RsaTests = struct {
	name   string
	pubKey []byte
	priKey []byte
	in     []byte
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
