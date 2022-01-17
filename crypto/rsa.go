// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/1/17 10:05:45
// * File: aes.go
// * Proj: go-tools
// * Pack: crypto
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * 	-RsaEncrypt(decrypted, pubKey []byte) ([]byte, error)
// * 	-RsaDecrypt(encrypted, priKey []byte) ([]byte, error)
// * 	-GenRsaKey(priWriter, pubWriter io.Writer, bits int) error
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/1/17 10:07:01 ColeCai.
// ***********************************************************************************************
func RsaEncrypt(decrypted, puKey []byte) ([]byte, error) {
	block, _ := pem.Decode(puKey)
	if block == nil {
		return nil, errors.New("invalid rsa public key")
	}

	pubInfo, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInfo.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, decrypted)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/1/17 10:10:47 ColeCai.
// ***********************************************************************************************
func RsaDecrypt(encrypted, priKey []byte) ([]byte, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("invalid rsa private key")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, pri, encrypted)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/1/17 10:14:13 ColeCai.
// ***********************************************************************************************
func GenRsaKey(priWriter, pubWriter io.Writer, bits int) error {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return errors.WithStack(err)
	}

	dPriStream := x509.MarshalPKCS1PrivateKey(priKey)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: dPriStream}
	err = pem.Encode(priWriter, block)
	if err != nil {
		return errors.WithStack(err)
	}

	pubKey := &priKey.PublicKey
	dPubStream, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return errors.WithStack(err)
	}
	block = &pem.Block{Type: "RSA PUBLIC KEY", Bytes: dPubStream}
	return pem.Encode(pubWriter, block)
}
