package cryptoutil

import "errors"

// Ciphertext blob formats.
//
// Every symmetric ciphertext Citadel has ever produced is one of:
//
//	legacy  nonce || ciphertext || tag                    (no header)
//	v1      0x01 | len(keyID) | keyID | nonce || ct || tag
//	v2      0x02 | len(keyID) | keyID | len(materialID) | materialID | nonce || ct || tag
//
// v1 and legacy blobs were sealed with a key's original material. v2 blobs
// name the key-material version they were sealed with, so a key can rotate
// its material and still open everything sealed before. A key that has never
// rotated keeps writing v1, so older Citadel builds can still read what new
// ones write until the first rotation.
const CipherBlobVersionV2 byte = 2

// minSealedLen is the shortest AES-GCM output: a nonce and a tag.
const minSealedLen = GCMNonceSize + 16

// ParsedBlob is a decoded ciphertext blob. When Header is false the blob had
// no recognisable header and Sealed is the whole input (a legacy blob).
type ParsedBlob struct {
	Header     bool
	Version    byte
	KeyID      string
	MaterialID string
	Sealed     []byte
}

// ParseCipherBlob decodes any supported blob format. It never fails: input
// that does not parse as v1 or v2 is reported as a headerless legacy blob.
// Because a legacy blob starts with a random nonce, a parsed header can be a
// coincidence; callers that fail to open the parsed form should retry with
// the whole blob as legacy (see Legacy).
func ParseCipherBlob(blob []byte) ParsedBlob {
	legacy := ParsedBlob{Sealed: blob}
	if len(blob) < 2 {
		return legacy
	}
	switch blob[0] {
	case CipherBlobVersionV1:
		keyLen := int(blob[1])
		if keyLen == 0 || len(blob) < 2+keyLen+minSealedLen {
			return legacy
		}
		return ParsedBlob{Header: true, Version: CipherBlobVersionV1, KeyID: string(blob[2 : 2+keyLen]), Sealed: blob[2+keyLen:]}
	case CipherBlobVersionV2:
		keyLen := int(blob[1])
		if keyLen == 0 || len(blob) < 2+keyLen+1 {
			return legacy
		}
		matLen := int(blob[2+keyLen])
		rest := blob[3+keyLen:]
		if matLen == 0 || len(rest) < matLen+minSealedLen {
			return legacy
		}
		return ParsedBlob{
			Header:     true,
			Version:    CipherBlobVersionV2,
			KeyID:      string(blob[2 : 2+keyLen]),
			MaterialID: string(rest[:matLen]),
			Sealed:     rest[matLen:],
		}
	default:
		return legacy
	}
}

// EncryptBlobWithMaterial seals plaintext with raw key material and frames
// it: v2 naming materialID when one is given, v1 otherwise.
func EncryptBlobWithMaterial(material []byte, keyID, materialID string, plaintext, aad []byte) ([]byte, error) {
	if materialID == "" {
		return EncryptBlob(material, keyID, plaintext, aad)
	}
	if keyID == "" || len(keyID) > 255 || len(materialID) > 255 {
		return nil, errors.New("key or material id too long for blob header")
	}
	sealed, err := GCMSeal(material, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(keyID)+len(materialID)+len(sealed))
	out = append(out, CipherBlobVersionV2, byte(len(keyID)))
	out = append(out, keyID...)
	out = append(out, byte(len(materialID)))
	out = append(out, materialID...)
	out = append(out, sealed...)
	return out, nil
}
