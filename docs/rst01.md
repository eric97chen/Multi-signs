方案：
[How to Leak a Secret](https://people.csail.mit.edu/rivest/pubs/RST01.pdf)

大概思路：rsa体系可以使用公钥加密，私钥解密，这里的加密过程我们可以理解成一个 one-way permutation ,$f(x) = x^e$
,只有拥有对应私钥的人可以进行$f(x)$的逆运算，$f^-1(x)=x^d$(不要用标准库中的rsa解密当作逆函数)

然后方案中还需要一个combining function（简称cb，方案中给出了一个满足的cb：
$C_{k,v}(y_1,y_2,...,y_r)=E_k(y_r⊕E_k(y_{r−1}⊕E_k(y_{r−2}⊕E_k(...⊕E_k(y_1⊕v)...))))$,$E_k$是以k为密钥的对称加密算法，v是一个随机值，$k=hash(msg)$,
cb可以是任意的满足方案中的那三个条件的运算，简单来说，这三个条件就是为了不让$cb=v$可以化简，使得跟v有关的项可以左移或右移到等号的某一边

签名的时候，选择一组公钥$P_i,i \in 0,\cdots,r$,这组公钥包括signer的公钥，s是signer的公钥在这组公钥中的index,随机生成$x_i,i \in 0,\cdots,r，i\neq s$,根据每个每个公钥对应的one-way permutation去计算$y_i= f(x_i)$,将$y_i,代入C_{k,v}(y_1,y_2,...,y_r) = v$,这样我们就可以反推出一个$y_s$,通过私钥进行逆运算，如果singer不知道公钥组中的至少任意一个公钥对应的私钥，然后他直接取$y_s$为一个随机数，那么寻找一个v使得等式成立的难度非常的大，算出$x_s$,签名就是$(P_1,P_2,...,P_r;v;x_1,x_2,...,x_r)$

验证的时候把签名中的值代入cb，判断cb的值是否和v相等，如果相等签名有效，同时验证者无法判断签名者的公钥是公钥组中的哪一个
