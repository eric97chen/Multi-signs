- func Keygen(n int) (*Manager, []*User)
Keygen是群签名中一个群初始化的方法，参数n是初始化群成员的个数，Manager是群管理者，[]*User是所有群成员

- func (u *User) Sign(msg []byte) *Signature 
Sign是一个群成员对某个消息进行签名的方法，msg是消息本身，函数返回最后的签名

- func (s *Signature) Verify() bool 
Verify是一个签名验证的方法，返回验证签名的结果

- func (m *Manager) Open(sig *Signature) (*pbc.Element, error)
Open是一个群管理者追溯某个签名的签名者的方法，函数内会先对签名的有效性进行验证，无效的签名会返回error。如果签名有效函数返回一个群管理者授予的签名证书A，如果在群初始化的时候群管理者有保存所有群成员的证书Ai的话，那么管理者可以遍历Ai和A比较，找出签名的签名者