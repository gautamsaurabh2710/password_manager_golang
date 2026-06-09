package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func GenerateTransportKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func PublicKeyPEM(privateKey *rsa.PrivateKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func DecryptTransportValue(privateKey *rsa.PrivateKey, encodedCipher string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encodedCipher)
	if err != nil {
		return "", err
	}

	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func EncryptForBrowser(publicKeyPEM, plainText string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("invalid public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("invalid RSA public key")
	}

	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, []byte(plainText), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}
