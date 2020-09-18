package eddsa_

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"

	ed25519 "github.com/agl/ed25519/edwards25519"
)

type (
	Edwards25519 struct {
		*elliptic.CurveParams
	}
)

func CurveEdwards25519() *Edwards25519 {
	e := &Edwards25519{CurveParams: new(elliptic.CurveParams)}
	e.P = new(big.Int)
	e.N = new(big.Int)
	e.Gx, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	e.Gy, _ = new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	e.P.SetBit(zero, 255, 1).Sub(e.P, new(big.Int).SetInt64(19))

	l, _ := hex.DecodeString("14def9dea2f79cd65812631a5cf5d3ed")
	e.N.SetBit(zero, 252, 1).Add(e.N, new(big.Int).SetBytes(l))

	return e
}

func (e *Edwards25519) Params() *elliptic.CurveParams {
	return e.CurveParams
}

func (curve *Edwards25519) IsOnCurve(x, y *big.Int) bool {
	fex := big2fe(x)
	fey := big2fe(y)
	var x2, y2, dx2y2 ed25519.FieldElement
	ed25519.FeSquare(&x2, fex)
	ed25519.FeSquare(&y2, fey)

	ed25519.FeMul(&dx2y2, &x2, &y2)
	ed25519.FeMul(&dx2y2, &dx2y2, &fed)

	ed25519.FeSub(&y2, &y2, &x2)
	ed25519.FeSub(&y2, &y2, &feOne)
	ed25519.FeSub(&y2, &y2, &dx2y2)

	al := &y2
	bigAl := fe2big(al)
	return new(big.Int).Mod(bigAl, curve.Params().N).Cmp(zero) == 0 &&
		new(big.Int).Mod(bigAl, cofactor).Cmp(zero) == 0
}

func (e *Edwards25519) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	EGE1 := bigPoint2ege(x1, y1)
	EGE2 := bigPoint2ege(x2, y2)

	var y1minusX1, y2minusX2, y1plusX1, y2plusX2 ed25519.FieldElement
	var A, B, C, D, E, F, G, H, tmp ed25519.FieldElement
	ed25519.FeSub(&y1minusX1, &EGE1.Y, &EGE1.X)
	ed25519.FeSub(&y2minusX2, &EGE2.Y, &EGE2.X)
	ed25519.FeAdd(&y1plusX1, &EGE1.Y, &EGE1.X)
	ed25519.FeAdd(&y2plusX2, &EGE2.Y, &EGE2.X)

	ed25519.FeMul(&A, &y1minusX1, &y2minusX2)
	ed25519.FeMul(&B, &y1plusX1, &y2plusX2)
	ed25519.FeMul(&tmp, &EGE1.T, &feTwo)
	ed25519.FeMul(&tmp, &tmp, &fed)
	ed25519.FeMul(&C, &tmp, &EGE2.T)
	ed25519.FeMul(&tmp, &EGE1.Z, &feTwo)
	ed25519.FeMul(&D, &tmp, &EGE2.Z)
	ed25519.FeSub(&E, &B, &A)
	ed25519.FeSub(&F, &D, &C)
	ed25519.FeAdd(&G, &D, &C)
	ed25519.FeAdd(&H, &B, &A)

	EGE3 := new(ed25519.ExtendedGroupElement)
	ed25519.FeMul(&EGE3.X, &E, &F)
	ed25519.FeMul(&EGE3.Y, &G, &H)
	ed25519.FeMul(&EGE3.T, &E, &H)
	ed25519.FeMul(&EGE3.Z, &F, &G)

	x, y, _ = extendedToBigAffine(EGE3)
	return x, y
}

func (e *Edwards25519) Double(x1, y1 *big.Int) (x, y *big.Int) {
	EGE := bigPoint2ege(x1, y1)
	EGE3 := new(ed25519.ExtendedGroupElement)
	var A, B, C, H, E, G, F, tmp ed25519.FieldElement

	ed25519.FeSquare(&A, &EGE.X)
	ed25519.FeSquare(&B, &EGE.Y)
	ed25519.FeSquare2(&C, &EGE.Z)
	ed25519.FeAdd(&H, &A, &B)
	ed25519.FeAdd(&tmp, &EGE.X, &EGE.Y)
	ed25519.FeSquare(&tmp, &tmp)
	ed25519.FeSub(&E, &H, &tmp)
	ed25519.FeSub(&G, &A, &B)
	ed25519.FeAdd(&F, &C, &G)
	ed25519.FeMul(&EGE3.X, &E, &F)
	ed25519.FeMul(&EGE3.Y, &G, &H)
	ed25519.FeMul(&EGE3.T, &E, &H)
	ed25519.FeMul(&EGE3.Z, &G, &F)

	x, y, _ = extendedToBigAffine(EGE3)
	return
}

func (curve *Edwards25519) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	kb := new(big.Int).SetBytes(k)
	rEGE := new(ed25519.ExtendedGroupElement)
	r := new(ed25519.CompletedGroupElement)
	rEGE.Zero()

	for i := kb.BitLen() - 1; i >= 0; i-- {
		rEGE.Double(r)
		r.ToExtended(rEGE)
		if kb.Bit(i) == 1 {
			x2, y2, _ := extendedToBigAffine(rEGE)
			x3, y3 := curve.Add(x1, y1, x2, y2)
			rEGE.FromBytes(bigPoint2bytes(x3, y3))
		}
	}
	x, y, _ = extendedToBigAffine(rEGE)
	return
}

func (e *Edwards25519) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return e.ScalarMult(e.Gx, e.Gy, k)
}
