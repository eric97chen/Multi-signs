package eddsa_

import (
	"math/big"

	ed25519 "github.com/agl/ed25519/edwards25519"
)

func bytez2byte32(bz []byte) *[32]byte {
	s := new([32]byte)
	lbz := len(bz)
	if lbz > felen {
		lbz = felen
	}

	for i := 0; i < lbz; i++ {
		s[i] = bz[lbz-i-1]
	}
	return s
}

func bigInt2bytes(n *big.Int) *[32]byte {
	return bytez2byte32(n.Bytes())
}

func big2fe(n *big.Int) *ed25519.FieldElement {
	fe := new(ed25519.FieldElement)
	ed25519.FeFromBytes(fe, bigInt2bytes(n))
	return fe
}

func fe2big(fe *ed25519.FieldElement) *big.Int {
	s := new([32]byte)
	ed25519.FeToBytes(s, fe)
	reverse(s[:])
	return new(big.Int).SetBytes(s[:])
}

func bigPoint2bytes(x, y *big.Int) *[32]byte {
	xbz := bigInt2bytes(x)
	ybz := bigInt2bytes(y)

	fey := new(ed25519.FieldElement)
	ed25519.FeFromBytes(fey, xbz)
	isneg := ed25519.FeIsNegative(fey) == 1

	if isneg {
		ybz[31] |= byte(128)
	} else {
		ybz[31] &^= byte(128)
	}
	return ybz
}

func bigPoint2ege(x, y *big.Int) *ed25519.ExtendedGroupElement {
	e := new(ed25519.ExtendedGroupElement)
	e.FromBytes(bigPoint2bytes(x, y))
	return e
}

func extendedToBigAffine(ege *ed25519.ExtendedGroupElement) (*big.Int, *big.Int, bool) {
	var deno, x, y ed25519.FieldElement
	ed25519.FeInvert(&deno, &ege.Z)

	ed25519.FeMul(&x, &deno, &ege.X)
	ed25519.FeMul(&y, &deno, &ege.Y)
	return fe2big(&x), fe2big(&y), ed25519.FeIsNegative(&x) == 1
}

func reverse(bz []byte) {
	for i, j := 0, len(bz)-1; i < j; i, j = i+1, j-1 {
		bz[i], bz[j] = bz[j], bz[i]
	}
}
