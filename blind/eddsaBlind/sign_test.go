package blind

import (
	eddsa "signs/blind/curve"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSig(t *testing.T) {
	Msg := []byte("blind signature")
	BZlen := 35

	Key := eddsa.GetRandMod(random())
	KnownPubkey := eddsa.ScalarBaseMul(Key)
	sp := &EddsaPair{key: Key, pub: KnownPubkey}
	user := new(User)

	sign := NewSign(sp)
	c_, err := user.CalcC(Msg, BZlen, sign.KG(), KnownPubkey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("c:%d\n", c_)

	s_ := sign.Calcs_(c_)
	t.Logf("s:%d\n", s_)

	user.CalcS(s_)

	sig := user.GetSign()
	// t.Log(sig)
	assert.True(t, sig.Verify(KnownPubkey))
}

func BenchmarkSign(b *testing.B) {
	Msg := []byte("blind signature")
	BZlen := 35

	Key := eddsa.GetRandMod(random())
	KnownPubkey := eddsa.ScalarBaseMul(Key)
	sp := &EddsaPair{key: Key, pub: KnownPubkey}
	user := new(User)

	sign := NewSign(sp)
	for i := 0; i < b.N; i++ {
		c_, err := user.CalcC(Msg, BZlen, sign.KG(), KnownPubkey)
		if err != nil {
			b.Fatal(err)
		}
		s_ := sign.Calcs_(c_)
		user.CalcS(s_)
	}
}

func BenchmarkVerify(b *testing.B) {
	Msg := []byte("blind signature")
	BZlen := 35

	Key := eddsa.GetRandMod(random())
	KnownPubkey := eddsa.ScalarBaseMul(Key)
	sp := &EddsaPair{key: Key, pub: KnownPubkey}
	user := new(User)

	sign := NewSign(sp)
	c_, err := user.CalcC(Msg, BZlen, sign.KG(), KnownPubkey)
	if err != nil {
		b.Fatal(err)
	}
	s_ := sign.Calcs_(c_)
	user.CalcS(s_)
	sig := user.GetSign()
	for i := 0; i < b.N; i++ {
		assert.True(b, sig.Verify(KnownPubkey))
	}
}
