package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

// Passphrase-encrypted PKCS#8 (RFC 5958 EncryptedPrivateKeyInfo with RFC 8018
// PBES2), as returned by ACM ExportCertificate. Only FIPS-approved pieces are
// used: PBKDF2 with HMAC-SHA-256 (128-bit salt) and AES-256-CBC. The Go
// standard library can parse PKCS#8 but not encrypt it, hence this file.
// OpenSSL reads the result with `openssl pkey -in key.pem -passin ...`.

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

const (
	pbes2Iterations = 600000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
	pbes2SaltLen    = 16
	// pbes2MaxIterations bounds decryption work for untrusted input.
	pbes2MaxIterations = 10_000_000
)

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

func rawASN1(v any) (asn1.RawValue, error) {
	b, err := asn1.Marshal(v)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// encryptPKCS8PEM encrypts a DER PKCS#8 private key under passphrase and
// returns an "ENCRYPTED PRIVATE KEY" PEM block.
func encryptPKCS8PEM(pkcs8DER, passphrase []byte) ([]byte, error) {
	return encryptPKCS8PEMIter(pkcs8DER, passphrase, pbes2Iterations)
}

func encryptPKCS8PEMIter(pkcs8DER, passphrase []byte, iterations int) ([]byte, error) {
	salt := make([]byte, pbes2SaltLen)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(pkcs8DER)%aes.BlockSize
	plain := append(bytes.Clone(pkcs8DER), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	clear(plain)
	clear(key)

	nullParams := asn1.RawValue{Tag: asn1.TagNull}
	kdf, err := rawASN1(pbkdf2Params{Salt: salt, IterationCount: iterations, KeyLength: 32,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: nullParams}})
	if err != nil {
		return nil, err
	}
	ivRaw, err := rawASN1(iv)
	if err != nil {
		return nil, err
	}
	params, err := rawASN1(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: kdf},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: ivRaw},
	})
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: params},
		EncryptedData: ct,
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), nil
}

var errPBES2 = errors.New("unsupported or corrupt encrypted private key")

// decryptPKCS8PEM reverses encryptPKCS8PEM. It accepts only the PBES2 /
// PBKDF2-HMAC-SHA256 / AES-256-CBC combination produced above.
func decryptPKCS8PEM(pemBytes, passphrase []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, errPBES2
	}
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(block.Bytes, &info); err != nil || len(rest) > 0 || !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errPBES2
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errPBES2
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) || !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, errPBES2
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, errPBES2
	}
	if !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) || kdf.IterationCount < 1 || kdf.IterationCount > pbes2MaxIterations ||
		(kdf.KeyLength != 0 && kdf.KeyLength != 32) {
		return nil, errPBES2
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errPBES2
	}
	if len(info.EncryptedData) == 0 || len(info.EncryptedData)%aes.BlockSize != 0 {
		return nil, errPBES2
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), kdf.Salt, kdf.IterationCount, 32)
	if err != nil {
		return nil, errPBES2
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, errPBES2
	}
	plain := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(plain, info.EncryptedData)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, errPBES2
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errPBES2
		}
	}
	return plain[:len(plain)-pad], nil
}
