环签名是基于rsa实现的，所以时候的公私钥对是rsa的公私钥对，该环签名的实现没有使用第三方库，用的都是go的标准库，所以rsa的公私钥对的生成使用标准库中的rsa公私钥对生成。

```go
func RingSign(msg []byte, pubkeys []*rsa.PublicKey, index int, prikey *rsa.PrivateKey) (*Signature, error)
```
其中pubkeys是环签名中的公钥环，pubkeys[index]是signer的公钥,prikey是signer的私钥

```go
func (s *Signature) Verify() (res bool) 
```

