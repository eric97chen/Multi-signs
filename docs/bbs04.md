## BBS04

#### 参考
[Short Group Signature(bbs04)](https://crypto.stanford.edu/dabo/papers/groupsigs.pdf)

#### 方案
bbs04.5 & .4 中已经介绍的比较清楚了，这里对签名和验证中的一些证明进行补充和分析

bilinear group（以下简称bg）介绍:

$G1,G2是以p为阶循环群，且同构，g1是G1的生成元，g2是G2的生成元  \phi(g2)=g1,e是一个易计算的映射,$$e:G1 \times G2 \rightarrow GT,且满足：$

- $u\in G1,v \in G2且a,b \in Z，e(u^a,v^b) = e(u,v)^{ab}$
- $e(g1,g2) \neq 1$

4.protocol 1.(1)中 $e(T_3,g_2)^x\cdot e(h,w)^{-\alpha -\beta}\cdot e(h,g_2)^{-\delta_1 - \delta_2} = e(g_1,g_2)/e(T_3,w)$（式1）

$左边 = e(T_3,g_2)^x\cdot e(A/T_3,g_2)^{\gamma}\cdot e(A/T_3,g_2)^{x}$

$左边 \times e(T_3,w) = e(T_3,g_2)^{x+\gamma} \cdot e(A/T_3,g_2)^{x+\gamma} = $$e(T_3,wg_2^{x}) \cdot e(A/T_3,wg_2^{x})$

bg还有一些性质在bbs04中没有提及，因为bbs04只是对bg进行引用，根据

- [1](https://yq.aliyun.com/articles/763967),这里bg中的G1，G2是加法群，满足$e(A+B,C) = e(A,C)\cdot e(B,C)$

所以如果bbs04中的G1，G2如果是乘法群的话,$左边 \times e(T_3,w) = e(A,wg_2^{x})$,

而在bbs04.2中：G1 and G2 are two (multiplicative) cyclic groups of prime order p.
所以$左边 \times e(T_3,w) = e(A,wg_2^{x})$是成立的，而如果式1成立，那么可以证明$ e(g_1,g_2) = e(A,wg_2^{x} $), 即$A^{x+\gamma} = g_1$(bbs04.4中)，那么就可以说明了，A是群管理者授予某个以x为secret key的群成员的一个有效的签名证书。

以上一个签名中的参数$T_1,T_2,T_3$存在的意义

而要让bbs04.4 （1）中的等式都成立，需要给出符合条件的的$\alpha,\beta,\delta_1,\delta_2,x$,但是$x，A$对于群成员来说私密的，所以需要通过零知识证明(schnnor)来证明某个签名者知道以上五个参数的值

通过以上就可以构造出一个被诚实验证者验证正确的签名$(T_1,T_2,T_3,c,s_1,s_2,s_3,s_4,s_5)$。