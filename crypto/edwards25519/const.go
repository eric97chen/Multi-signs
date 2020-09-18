package eddsa_

import (
	"math/big"

	ed25519 "github.com/agl/ed25519/edwards25519"
)

var (
	felen    = 32
	zero     = new(big.Int).SetInt64(0)
	two      = new(big.Int).SetInt64(2)
	cofactor = new(big.Int).SetInt64(8)
	fed      = ed25519.FieldElement{
		-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116,
	}
	feOne = ed25519.FieldElement{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	feTwo = ed25519.FieldElement{
		2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
)
