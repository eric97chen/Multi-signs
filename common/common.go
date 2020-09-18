package common

import (
	xrand "crypto/rand"
	"crypto/sha256"
	"math/big"
	"math/rand"
	"time"
)

func Hash256(args ...[]byte) []byte {
	h := sha256.New()
	h.Reset()
	for i := range args {
		h.Write(args[i])
	}
	return h.Sum(nil)
}

func Random() *rand.Rand {
	seed := time.Now().UnixNano()
	return rand.New(rand.NewSource(seed))
}

func Prime(bits int) (*big.Int, error) {
	p, err := xrand.Prime(Random(), bits)
	if err != nil {
		return nil, err
	}
	return p, nil
}
