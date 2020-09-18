package eddsa

import (
	"math/big"
	"testing"

	comm "signs/common"

	"github.com/stretchr/testify/assert"
)

func TestScalarBaseMul(t *testing.T) {
	bz1 := make([]byte, 32)
	bz2 := make([]byte, 32)
	comm.Random().Read(bz1)
	comm.Random().Read(bz2)
	b1 := new(big.Int).SetBytes(bz1)
	b2 := new(big.Int).SetBytes(bz2)
	b3 := new(big.Int).Add(b1, b2)
	p3 := ScalarBaseMul(b3)
	p1 := ScalarBaseMul(b1)
	p2 := ScalarBaseMul(b2)
	p0, err := p1.Add(p2)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, p3.GetX().Cmp(p0.GetX()) == 0)
}
