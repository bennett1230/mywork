"# Project 5" 
# 简介
本实验实现了国密SM2椭圆曲线数字签名算法的基础版和优化版，均为纯Python实现，不依赖第三方国密库。

基础实现采用普通仿射坐标，便于理解SM2算法原理。
优化实现通过学习gmssl库的优化方法，采用Jacobian坐标加速椭圆曲线点乘，并输出国密标准的签名格式，性能和兼容性更好。
## 代码结构
### 1. 椭圆曲线参数
定义了SM2推荐的椭圆曲线参数，包括素数p、系数a、b、基点G、阶n等。

### 2. 基础实现部分
逆元计算：inverse_mod，用于模逆运算。

点加/点倍加/标量乘：point_add、point_double、scalar_mult，实现椭圆曲线上的基本运算。

密钥生成：gen_keypair_basic，生成私钥和公钥。

哈希函数：hash_msg，默认用SHA256（可替换为SM3）。

签名/验签：sign_basic、verify_basic，实现SM2签名与验签，签名输出为(r, s)元组。

### 3. 优化实现部分（Jacobian坐标）
Jacobian点加/点倍加/标量乘：jacobian_add、jacobian_double、jacobian_mult，大幅减少逆元运算，提高点乘效率。

Jacobian转仿射坐标：jacobian_to_affine，便于输出标准公钥。

签名格式转换：int_to_hex、sig_to_hex，将签名(r, s)拼接为64字节16进制字符串，兼容国密标准。

密钥生成：gen_keypair_optimized，Jacobian坐标下生成密钥对。

签名/验签：sign_optimized、verify_optimized，优化版SM2签名与验签，签名输出为国密格式字符串。
