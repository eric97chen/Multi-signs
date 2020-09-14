package bbs04

import (
	"errors"
	comm "signs/common"

	"github.com/Nik-U/pbc"
)

type (
	Gpk struct {
		g1, g2, h, u, v, omega    *pbc.Element
		hlpPair_homg, hlpPair_hg2 *pbc.Element
	}

	Gmsk struct {
		xi1, xi2 *pbc.Element
	}

	Gsk struct {
		A, x *pbc.Element
	}

	Manager struct {
		*Gpk
		msk *Gmsk
	}

	User struct {
		*Gpk
		sk *Gsk
	}

	Sigma struct {
		T1, T2, T3, c, sAlpha, sBeta, sX, sDelta1, sDelta2 *pbc.Element
	}

	Signature struct {
		gsk   *Gpk
		sigma *Sigma
		msg   []byte
	}
)

var (
	pair *pbc.Pairing
)

func init() {
	//use pbc.GenerateA, general usage
	// params := pbc.GenerateA(160, 512)

	//use pbc.GenerateD where message size is the primary concern, but speed is also important.
	// params, _ := pbc.GenerateD(9563, 160, 171, 500)

	// params := pbc.GenerateE(160, 1024)

	// params := pbc.GenerateF(160)

	params, _ := pbc.GenerateG(9563, 160, 171, 500)

	pair = params.NewPairing()
}

func randZr() *pbc.Element {
	return pair.NewZr().Rand()
}
func newZr() *pbc.Element {
	return pair.NewZr()
}

func randG1() *pbc.Element {
	return pair.NewG1().Rand()
}

func newG1() *pbc.Element {
	return pair.NewG1()
}

func newG2() *pbc.Element {
	return pair.NewG2()
}

func newGT() *pbc.Element {
	return pair.NewGT()
}

func calcHelper(h, omega, g2 *pbc.Element) (*pbc.Element, *pbc.Element) {
	return newGT().Pair(h, omega), newGT().Pair(h, g2)
}

func calcC(msg []byte, T1, T2, T3, R1, R2, R3, R4, R5 *pbc.Element) *pbc.Element {
	h := comm.Hash256(msg, T1.Bytes(), T2.Bytes(), T3.Bytes(), R1.Bytes(), R2.Bytes(), R3.Bytes(), R4.Bytes(), R5.Bytes())
	c := newZr().SetFromHash(h)
	return c
}

func Keygen(n int) (*Manager, []*User, error) {
	if n < 1 {
		return nil, nil, errors.New("n should be positive")
	}
	g1 := pair.NewG1()
	g2 := pair.NewG2()
	h := randG1()
	xi1 := randZr()
	xi2 := randZr()
	u := newG1().PowZn(h, newZr().Invert(xi1))
	v := newG1().PowZn(h, newZr().Invert(xi2))
	gamma := randZr()
	omega := newG2().PowZn(g2, gamma)
	gpk := &Gpk{
		g1:    g1,
		g2:    g2,
		h:     h,
		u:     u,
		v:     v,
		omega: omega,
	}
	gpk.hlpPair_homg, gpk.hlpPair_hg2 = calcHelper(h, omega, g2)
	manager := &Manager{
		Gpk: gpk,
		msk: &Gmsk{xi1: xi1, xi2: xi2},
	}

	//generate for each user
	usrs := make([]*User, n)
	for i := 0; i < n; i++ {
		x := randZr()
		add := newZr().Add(gamma, x)
		invAdd := newZr().Invert(add)
		A := newG1().PowZn(g1, invAdd)
		usrs[i] = &User{
			Gpk: gpk,
			sk:  &Gsk{A: A, x: x},
		}
	}
	return manager, usrs, nil
}

func (u *User) Sign(msg []byte) (*Signature, error) {
	if len(msg) == 0 {
		return nil, errors.New("Empty message")
	}
	gsk := u.Gpk
	A := u.sk.A
	x := u.sk.x

	alpha := newZr()
	beta := newZr()
	T1 := newG1().PowZn(gsk.u, alpha)
	T2 := newG1().PowZn(gsk.v, beta)
	add := newZr().Add(alpha, beta)
	powAdd := pair.NewG1().PowZn(gsk.h, add)
	T3 := newG1().Mul(A, powAdd)
	delta1 := newZr().Mul(x, alpha)
	delta2 := newZr().Mul(x, beta)
	rAlpha := randZr()
	rBeta := randZr()
	rX := randZr()
	rDelta1 := randZr()
	rDelta2 := randZr()

	R1 := newG1().PowZn(gsk.u, rAlpha)
	R2 := newG1().PowZn(gsk.v, rBeta)
	pairT3g2 := newGT().Pair(T3, gsk.g2)
	tmp1 := newGT().PowZn(pairT3g2, rX)
	tmp2 := newGT().PowZn(gsk.hlpPair_homg, newZr().Add(newZr().Neg(rAlpha), newZr().Neg(rBeta)))
	tmp3 := newGT().PowZn(gsk.hlpPair_hg2, newZr().Add(newZr().Neg(rDelta1), newZr().Neg(rDelta2)))
	R3 := newGT().Mul(newGT().Mul(tmp1, tmp2), tmp3)
	R4 := newG1().Mul(newG1().PowZn(T1, rX),
		newG1().PowZn(gsk.u, newZr().Neg(rDelta1)))
	R5 := newG1().Mul(newG1().PowZn(T2, rX),
		newG1().PowZn(gsk.v, newZr().Neg(rDelta2)))

	c := calcC(msg, T1, T2, T3, R1, R2, R3, R4, R5)

	sAlpha := newZr().Add(rAlpha, newZr().Mul(c, alpha))
	sBeta := newZr().Add(rBeta, newZr().Mul(c, beta))
	sX := newZr().Add(rX, newZr().Mul(c, x))
	sDelta1 := newZr().Add(rDelta1, newZr().Mul(c, delta1))
	sDelta2 := newZr().Add(rDelta2, newZr().Mul(c, delta2))
	sig := Sigma{
		T1:      T1,
		T2:      T2,
		T3:      T3,
		c:       c,
		sAlpha:  sAlpha,
		sBeta:   sBeta,
		sX:      sX,
		sDelta1: sDelta1,
		sDelta2: sDelta2,
	}
	return &Signature{
		sigma: &sig,
		gsk:   gsk,
		msg:   msg,
	}, nil
}

func (s *Signature) Verify() bool {
	gsk := s.gsk
	msg := s.msg
	sigma := s.sigma

	negc := newZr().Neg(sigma.c)
	negsDelta1 := newZr().Neg(sigma.sDelta1)
	negsDelta2 := newZr().Neg(sigma.sDelta2)
	R1 := newG1().Mul(newG1().PowZn(gsk.u, sigma.sAlpha),
		newG1().PowZn(sigma.T1, negc))
	R2 := newG1().Mul(newG1().PowZn(gsk.v, sigma.sBeta),
		newG1().PowZn(sigma.T2, negc))
	tmp1 := newGT().PowZn(newGT().Pair(sigma.T3, gsk.g2), sigma.sX)
	tmp2 := newGT().PowZn(gsk.hlpPair_homg,
		newZr().Add(newZr().Neg(sigma.sAlpha), newZr().Neg(sigma.sBeta)))
	tmp3 := newGT().PowZn(gsk.hlpPair_hg2,
		newZr().Add(negsDelta1, negsDelta2))
	pairG1g2 := newGT().Pair(gsk.g1, gsk.g2)
	pairT3omg := newGT().Pair(sigma.T3, gsk.omega)
	tmp4 := newGT().PowZn(newGT().Div(pairG1g2, pairT3omg), sigma.c)
	mul := newGT().Mul(tmp1, tmp2)
	mul = newGT().Mul(mul, tmp3)
	R3 := newGT().Mul(mul, tmp4)
	R4 := newG1().Mul(newG1().PowZn(sigma.T1, sigma.sX),
		newG1().PowZn(gsk.u, negsDelta1))
	R5 := newG1().Mul(newG1().PowZn(sigma.T2, sigma.sX),
		newG1().PowZn(gsk.v, negsDelta2))

	c := calcC(msg, sigma.T1, sigma.T2, sigma.T3, R1, R2, R3, R4, R5)
	return c.Equals(sigma.c)
}

func (m *Manager) Open(sig *Signature) (*pbc.Element, error) {
	if !sig.Verify() {
		return nil, errors.New("Signature is valid")
	}
	sigma := sig.sigma
	gmsk := m.msk
	tmp1 := newG1().PowZn(sigma.T1, gmsk.xi1)
	tmp2 := newG1().PowZn(sigma.T2, gmsk.xi2)
	return newG1().Div(sigma.T3, newG1().Mul(tmp1, tmp2)), nil
}
