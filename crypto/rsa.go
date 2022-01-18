// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/01/17 10:05:45
// * File: rsa.go
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
	"crypto"
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
// *    -create: 2021/01/17 10:07:01 ColeCai.
// ***********************************************************************************************
func RsaEncrypt(decrypted, puKey []byte) ([]byte, error) {
	pub, err := GenRsaPubKey(puKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, decrypted)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/01/17 10:10:47 ColeCai.
// ***********************************************************************************************
func RsaDecrypt(encrypted, priKey []byte) ([]byte, error) {
	pri, err := GenRsaPriKey(priKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, pri, encrypted)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/01/17 10:14:13 ColeCai.
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

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/17 12:17:34 ColeCai.
// ***********************************************************************************************
func GenRsaPKCS8Key(bits int) (string, string, error) {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	dPriStream, err := x509.MarshalPKCS8PrivateKey(priKey)
	if err != nil {
		return "", "", err
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: dPriStream}
	pri := pem.EncodeToMemory(block)
	dPubStream, err := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	block = &pem.Block{Type: "RSA PUBLIC KEY", Bytes: dPubStream}
	pub := pem.EncodeToMemory(block)
	return string(pri), string(pub), nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/17 11:21:34 ColeCai.
// ***********************************************************************************************
func RsaSign(src []byte, priKey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/17 11:28:27 ColeCai.
// ***********************************************************************************************
func RsaVerify(src, sign []byte, pubKey *rsa.PublicKey, hash crypto.Hash) error {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, sign)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/17 11:34:20 ColeCai.
// ***********************************************************************************************
func GenRsaPriKey(priKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("invalid rsa private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/01/17 11:36:57 ColeCai.
// ***********************************************************************************************
func GenRsaPubKey(pubKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("invalid rsa public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}
