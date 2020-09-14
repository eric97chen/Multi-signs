package rst01

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"math/big"
	mrand "math/rand"
	comm "signs/common"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEk(t *testing.T) {
	msg := "ring signature"
	msgHash := comm.Hash256([]byte(msg))
	key := comm.Hash256(msgHash)
	e, err := NewEsymm(key)
	if err != nil {
		log.Fatal(err)
	}
	bz, err := e.Encrypt(msgHash)
	if err != nil {
		log.Fatal(err)
	}
	bz1, err := e.Decrypt(bz)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, strings.Compare(string(msgHash), string(bz1)) == 0)
}

func TestGi1(t *testing.T) {
	myrand := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	wkoutbz := make([]byte, 256)
	myrand.Read(wkoutbz)
	prikey, err := rsa.GenerateKey(rand.Reader, priBits)
	e := new(big.Int).SetInt64(int64(prikey.E))
	n := prikey.N
	d := prikey.D
	if err != nil {
		log.Fatal(err)
	}
	bigZ := new(big.Int).SetBytes(wkoutbz)
	x := new(big.Int).Exp(bigZ, d, n)
	y := new(big.Int).Exp(x, e, n)
	t.Logf("%x\n", bigZ.Bytes())
	t.Logf("%x\n", y.Bytes())
	assert.True(t, bigZ.Cmp(y) == 0)
}

func TestSign(t *testing.T) {
	index := 9
	msg := []byte("xxxxxx")
	num := 10
	pubs := make([]*rsa.PublicKey, num)
	var pri *rsa.PrivateKey
	for i := 0; i < num; i++ {
		prikey, _ := rsa.GenerateKey(comm.Random(), priBits)
		pubs[i] = &prikey.PublicKey
		if i == index {
			pri = prikey
		}
	}
	sig, err := RingSign(msg, pubs, index, pri)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, sig.Verify())
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("xxxxxx")
	num := 2
	index := 1
	pubs := make([]*rsa.PublicKey, num)
	var pri *rsa.PrivateKey
	for i := 0; i < num; i++ {
		prikey, _ := rsa.GenerateKey(comm.Random(), priBits)
		pubs[i] = &prikey.PublicKey
		if i == index {
			pri = prikey
		}
	}
	for i := 0; i < b.N; i++ {
		RingSign(msg, pubs, index, pri)
	}
}

func BenchmarkVerify(b *testing.B) {
	index := 1
	msg := []byte("xxxxxx")
	num := 2
	pubs := make([]*rsa.PublicKey, num)
	var pri *rsa.PrivateKey
	for i := 0; i < num; i++ {
		prikey, _ := rsa.GenerateKey(comm.Random(), priBits)
		pubs[i] = &prikey.PublicKey
		if i == index {
			pri = prikey
		}
	}
	sig, err := RingSign(msg, pubs, index, pri)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		sig.Verify()
	}
}
