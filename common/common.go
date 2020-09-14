package common

import (
	"crypto/sha256"
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

//SafePrime
