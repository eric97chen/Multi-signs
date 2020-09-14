package rst01

import (
	"crypto/rsa"
	"errors"
	comm "signs/common"
	"strings"
)

type (
	Signature struct {
		msg     []byte
		pubkeys []*rsa.PublicKey
		v       []byte
		xi      [][]byte
	}
)

func (s *Signature) Verify() (res bool) {
	xi := s.xi
	pubkeys := s.pubkeys

	k := comm.Hash256(s.msg)
	e, _ := NewEsymm(k)

	yi := make([][]byte, len(xi))
	for i := range xi {
		yi[i] = gi(xi[i], pubkeys[i])
	}

	ckv := trv(e, len(xi)-1, yi, s.v)
	res = strings.Compare(string(s.v), string(ckv)) == 0
	return
}

func validPubs(pubkeys []*rsa.PublicKey) bool {
	if pubkeys == nil {
		return false
	}
	for i := range pubkeys {
		if pubkeys[i] == nil {
			return false
		}
	}
	return true
}

func RingSign(msg []byte, pubkeys []*rsa.PublicKey, index int, prikey *rsa.PrivateKey) (*Signature, error) {
	if msg == nil || !validPubs(pubkeys) || prikey == nil {
		return nil, errors.New("Invalid parameters")
	}
	if len(msg) == 0 {
		return nil, errors.New("Nothing to sign")
	}
	if len(pubkeys) < 2 ||
		index <= 0 ||
		index > len(pubkeys)-1 {
		return nil, errors.New("Invalid length of public keys or index is out of range")
	}

	if index == 0 {
		pubkeys[0], pubkeys[len(pubkeys)-1] = pubkeys[len(pubkeys)-1], pubkeys[0]
		index = len(pubkeys) - 1
	}

	k := comm.Hash256(msg)

	v := randBaseSize(comm.Random())
	xi := make([][]byte, len(pubkeys))
	y := make([][]byte, len(pubkeys))
	var err error
	for i := range xi {
		if i == index {
			continue
		}
		xi[i] = randBaseSize(comm.Random())
		y[i] = gi(xi[i], pubkeys[i])
	}

	e, _ := NewEsymm(k)
	ys, err := calcGiIndex(e, index, y, v)
	if err != nil {
		return nil, err
	}
	xs := invGi(ys, prikey)
	xi[index] = xs

	mbak := make([]byte, len(msg))
	copy(mbak, msg)
	sig := &Signature{
		msg:     mbak,
		pubkeys: pubkeys,
		v:       v,
		xi:      xi,
	}
	if !sig.Verify() {
		return RingSign(msg, pubkeys, index, prikey)
	}
	return sig, nil
}
