```go
func (s *Sign) KG() *eddsa.Point
```
signer随机生成k，计算kG，并返回
```go
func (u *User) CalcC(msg []byte, bzlen int, kg, knownPub *eddsa.Point) (*big.Int, error)
```
user随机生成$\gamma,\delta$,并根据signer的kg，计算$c^\prime$的值，并返回，参数bzlen是$\gamma,\delta$的位数，knownPub是已知的signer的公钥

```go
func (s *Sign) Calcs_(c *big.Int) *big.Int
```
signer根据user的$c^\prime$计算$s^\prime$

```go
func (u *User) CalcS(s_ *big.Int) *big.Int
```
user根据signer返回的$s^\prime$，计算s，最后通过GetSign方法获得完整签名


```go
	func (s *Signature) Verify(KnownPub *eddsa.Point) bool
```
一个盲签名的验证方法
