"# Project 5" 
# 一、基础实现（仿射坐标）
## 1. 椭圆曲线点运算
点加（point_add_basic）
按照椭圆曲线的仿射坐标公式实现，涉及一次逆元运算（即除法）。
点倍乘（point_double_basic）
也是仿射坐标公式，涉及一次逆元运算。
标量乘（scalar_mult_basic）
采用“二进制法”逐位扫描私钥，循环调用点加和点倍乘，效率较低。
## 2. 逆元运算
inverse_mod_basic
用扩展欧几里得算法实现模逆元，纯Python实现，速度一般。
## 3. 签名与验签
签名（sign_basic）
生成随机数k，计算kG，得到r和s，流程与SM2标准一致。
验签（verify_basic）
计算sG + tP，判断结果是否等于r。

# 二、手动优化实现（Jacobian坐标+内置pow逆元）
## 1. 椭圆曲线点运算优化
Jacobian坐标
点加、点倍乘都在Jacobian坐标下进行，避免了每次都做逆元运算。
只有在最终需要输出仿射坐标时，才做一次逆元运算，极大提升效率。
点加（jacobian_add）/点倍乘（jacobian_double）
采用Jacobian坐标公式，全部用模乘和模加，速度快。
Jacobian转仿射（jacobian_to_affine）
只在最后一步做一次逆元。
## 2. 逆元运算优化
inverse_mod
直接用Python 3.8+的pow(a, -1, m)，比扩展欧几里得算法快很多。
## 3. 标量乘优化
scalar_mult_jacobian
仍用二进制法，但每步都在Jacobian坐标下进行，效率提升显著。
## 4. 签名与验签
签名（sign_optimized）
与基础实现流程一致，只是点乘用Jacobian坐标加速。
验签（verify_optimized）
由于验签涉及点加，仍用仿射坐标（如需进一步优化可用Jacobian点加）。
