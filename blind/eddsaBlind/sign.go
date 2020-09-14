package blind

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"math/rand"
	"signs/crypto/eddsa"
	"time"
)

var (
	mixbtLen = 32
)

type (
	EddsaPair struct {
		key *big.Int
		pub *eddsa.Point
	}

	Sign struct {
		keys *EddsaPair
		tmpk *EddsaPair
	}

	User struct {
		gamma, delta, s, c *big.Int
		msg                []byte
	}

	Signature struct {
		c, s *big.Int
		msg  []byte
	}
)

func NewSign(keyPair *EddsaPair) *Sign {
	return &Sign{keys: keyPair}
}

func (s *Sign) kg() {
	k := eddsa.GetRandMod(random())
	s.tmpk = &EddsaPair{
		key: k,
		pub: eddsa.ScalarBaseMul(k),
	}
}

func (s *Sign) KG() *eddsa.Point {
	s.kg()
	return s.tmpk.pub
}

func (s *Sign) Calcs_(c *big.Int) *big.Int {
	k := s.tmpk.key
	cd := new(big.Int).Mul(c, s.keys.key)
	return new(big.Int).Sub(k, cd)
}

func (u *User) setRandom(bzlen int) error {
	if bzlen < mixbtLen {
		return errors.New("invalid bzlen")
	}
	gam := make([]byte, bzlen)
	del := make([]byte, bzlen)
	random().Read(gam)
	random().Read(del)
	u.gamma = new(big.Int).SetBytes(gam)
	u.delta = new(big.Int).SetBytes(del)
	return nil
}

func (u *User) CalcC(msg []byte, bzlen int, kg, knownPub *eddsa.Point) (*big.Int, error) {
	if msg == nil || len(msg) == 0 {
		return nil, errors.New("Nothing to sign")
	}
	if err := u.setRandom(bzlen); err != nil {
		return nil, err
	}
	if kg == nil || knownPub == nil {
		return nil, errors.New("nil Point on eddsa")
	}
	u.msg = msg
	pgam := eddsa.ScalarBaseMul(u.gamma)
	delQ := knownPub.ScalarMul(u.delta)
	A, _ := kg.Add(pgam, delQ)
	t := new(big.Int).Mod(A.GetX(), eddsa.Ec().Params().N)
	u.c = new(big.Int).SetBytes(hash(msg, t.Bytes()))
	c := new(big.Int).Sub(u.c, u.delta)
	if c.Sign() != -1 {
		return u.CalcC(msg, bzlen, kg, knownPub)
	}
	return c, nil
}

func (u *User) CalcS(s_ *big.Int) *big.Int {
	u.s = new(big.Int).Add(s_, u.gamma)
	return u.s
}

func (u *User) Getc() *big.Int {
	return u.c
}

func (u *User) Gets() *big.Int {
	return u.s
}

func (u *User) GetSign() *Signature {
	if u.c != nil && u.s != nil {
		m := make([]byte, len(u.msg))
		copy(m, u.msg)
		return &Signature{c: u.c, s: u.s, msg: m}
	}
	return nil
}

func (s *Signature) Verify(KnownPub *eddsa.Point) bool {
	cQ := KnownPub.ScalarMul(s.c)
	sG := eddsa.ScalarBaseMul(s.s)
	p, _ := cQ.Add(sG)
	h := new(big.Int).SetBytes(hash(s.msg, new(big.Int).Mod(p.GetX(), eddsa.Ec().Params().N).Bytes()))
	return s.c.Cmp(h) == 0
}

func random() *rand.Rand {
	src := rand.NewSource(time.Now().UnixNano())
	return rand.New(src)
}

func hash(args ...[]byte) []byte {
	h := sha256.New()
	h.Reset()
	for i := range args {
		h.Write(args[i])
	}
	return h.Sum(nil)
}
