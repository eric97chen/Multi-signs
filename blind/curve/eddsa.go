package eddsa

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	edwards "signs/crypto/edwards25519"
)

var (
	ec elliptic.Curve
)

type (
	Point struct {
		curve elliptic.Curve
		x, y  *big.Int
	}
)

func init() {
	ec = edwards.CurveEdwards25519()
}

func NewPoint(x, y *big.Int) (*Point, error) {
	if x == nil || y == nil {
		return nil, errors.New("point parameters should not be nil")
	}
	if !ec.IsOnCurve(x, y) {
		return nil, errors.New("Point is not on curve")
	}
	return &Point{
		curve: ec,
		x:     x,
		y:     y,
	}, nil
}

func (p *Point) ScalarMul(k *big.Int) *Point {
	bz := k.Bytes()
	x, y := p.curve.ScalarMult(p.x, p.y, bz)
	return &Point{
		curve: p.curve,
		x:     x,
		y:     y,
	}
}

func (p *Point) Add(ops ...*Point) (*Point, error) {
	if ops == nil || len(ops) == 0 {
		return nil, errors.New("nil or empty ops is invalid")
	}
	var x, y *big.Int
	for i := range ops {
		if i == 0 {
			x, y = p.curve.Add(p.x, p.y, ops[i].x, ops[i].y)
		} else {
			x, y = p.curve.Add(x, y, ops[i].x, ops[i].y)
		}
	}
	return NewPoint(x, y)
}

func (P *Point) GetX() *big.Int {
	return P.x
}

func ScalarBaseMul(k *big.Int) *Point {
	curve := ec
	x, y := curve.ScalarBaseMult(k.Bytes())
	p := &Point{
		curve: curve,
		x:     x,
		y:     y,
	}
	return p
}

func GetRandMod(rand io.Reader) *big.Int {
	n := ec.Params().N
	bzRand := make([]byte, n.BitLen()/8)
	rand.Read(bzRand)
	bigRand := new(big.Int).SetBytes(bzRand)
	if bigRand.Cmp(n) == 1 {
		return GetRandMod(rand)
	}
	return new(big.Int).Mod(bigRand, n)
}

func Ec() elliptic.Curve {
	return ec
}
