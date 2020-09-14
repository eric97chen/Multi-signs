package bbs04

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	msg := []byte("bbs04")
	_, usrs, _ := Keygen(1)
	sig, _ := usrs[0].Sign(msg)
	assert.True(t, sig.Verify())
}

func TestOpen(t *testing.T) {
	msg := []byte("bbs04")
	mag, usrs, _ := Keygen(1)
	sig, _ := usrs[0].Sign(msg)
	A, _ := mag.Open(sig)
	exp := A.Equals(usrs[0].sk.A)
	assert.True(t, exp)
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("bbs04")
	_, usrs, _ := Keygen(1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		usrs[0].Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("bbs04")
	_, usrs, _ := Keygen(1)
	sig, _ := usrs[0].Sign(msg)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sig.Verify()
	}
}

func TestSize(t *testing.T) {
	msg := []byte("bbs04")
	_, usrs, _ := Keygen(1)
	sig, _ := usrs[0].Sign(msg)
	sigma := sig.sigma
	l := sigma.T1.BytesLen() + sigma.T2.BytesLen() + sigma.T3.BytesLen() + sigma.c.BytesLen() +
		sigma.sAlpha.BytesLen() + sigma.sBeta.BytesLen() + sigma.sX.BytesLen() + sigma.sDelta1.BytesLen() + sigma.sDelta2.BytesLen()
	fmt.Println(l)
}
