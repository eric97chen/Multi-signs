package rst01

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
)

const (
	priBits      = 2048
	baseSize     = 256
	baseSizeByte = baseSize / 8
)

type (
	esymm struct {
		block cipher.Block
	}
)

func NewEsymm(key []byte) (*esymm, error) {
	if len(key) != 32 && len(key) != 16 {
		return nil, errors.New("The length of a valid key should be 32 or 16")
	}
	block, _ := aes.NewCipher(key)
	return &esymm{block: block}, nil
}

func (e *esymm) Encrypt(bz []byte) ([]byte, error) {
	if len(bz)%aes.BlockSize != 0 {
		return nil, errors.New("The length of bz to encrypt should be multiple of 16")
	}
	ciphertext := make([]byte, aes.BlockSize+len(bz))
	iv := ciphertext[:aes.BlockSize]

	mode := cipher.NewCBCEncrypter(e.block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], bz)
	return ciphertext[aes.BlockSize:], nil
}

func (e *esymm) Decrypt(bz []byte) ([]byte, error) {
	if len(bz)%aes.BlockSize != 0 {
		return nil, errors.New("The length of bz to decrypt should be multiple of 16")
	}
	plaintext := make([]byte, aes.BlockSize+len(bz))
	iv := plaintext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(e.block, iv)
	mode.CryptBlocks(plaintext[aes.BlockSize:], bz)
	return plaintext[aes.BlockSize:], nil
}

func randBaseSize(rand io.Reader) []byte {
	v := make([]byte, baseSize)
	rand.Read(v)
	return v
}

func randBaseSizeByte(rand io.Reader) []byte {
	v := make([]byte, baseSizeByte)
	rand.Read(v)
	return v
}

func gi(x []byte, pub *rsa.PublicKey) []byte {
	bigX := new(big.Int).SetBytes(x)
	e := new(big.Int).SetInt64(int64(pub.E))
	n := pub.N
	y := new(big.Int).Exp(bigX, e, n)
	return y.Bytes()
}

func invGi(y []byte, pri *rsa.PrivateKey) []byte {
	bigY := new(big.Int).SetBytes(y)
	d := pri.D
	n := pri.N
	x := new(big.Int).Exp(bigY, d, n)
	return x.Bytes()
}

//dst is changed
func xor(dst, src []byte) []byte {
	if len(dst) != len(src) {
		// panic("Invalid len(src) != len(dst)")
		return dst
	}
	for i := range dst {
		dst[i] = dst[i] ^ src[i]
	}
	return dst[:]
}

func trv(e *esymm, idx int, y [][]byte, v []byte) []byte {
	if idx == -1 {
		return v
	}
	ek, _ := e.Encrypt(xor(y[idx], trv(e, idx-1, y, v)))
	return ek
}

func uptrv(e *esymm, idx int, y [][]byte, v []byte) []byte {
	if idx == len(y) {
		dev, _ := e.Decrypt(v)
		return dev
	}
	de, _ := e.Decrypt(xor(y[idx], uptrv(e, idx+1, y, v)))
	return de
}

func calcGiIndex(e *esymm, idx int, y [][]byte, v []byte) ([]byte, error) {
	ek4 := trv(e, idx-1, y, v)
	dek6 := uptrv(e, idx+1, y, v)
	ys := xor(ek4, dek6)
	return ys, nil
}
