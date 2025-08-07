"# Project 4" 
# SM3 优化方法代码介绍
本实验包含了 SM3 哈希算法的基础实现（SM3_Basic）和优化实现（SM3_Optimized）。优化实现主要针对 Python 语言的运行特性，采用了多种软件优化手段，显著提升了哈希计算的效率。具体优化方法如下：

### 1. 循环左移（rotl）优化
优化版采用高效的位运算实现循环左移（_rotl_fast），避免了多余的掩码和分支判断，提升了每轮运算的速度。
### 2. T 常量旋转值预计算
SM3 算法每轮都需要用到 T 常量（T1、T2）的循环左移结果。
优化版在初始化时预先计算并缓存所有可能的 T 常量旋转值（self.t1_rotations、self.t2_rotations），主循环中直接查表，避免重复计算。
### 3. 消息扩展优化
优化版使用 struct.unpack('>16I', block) 一次性解包 16 个 32 位字，减少循环和类型转换的开销。
后续消息扩展和 W' 生成采用列表推导式，提升了 Python 代码的执行效率。
### 4. 主循环变量批量更新
优化版将主循环中的变量更新合并为批量赋值，减少临时变量和赋值次数，提升了代码执行速度。
### 5. 函数内联与简化
优化版将布尔函数（FF、GG）和置换函数（P0、P1）直接内联实现，减少了函数调用的开销。
### 6. 减少冗余对象创建
优化版尽量避免在主循环中创建新的对象或临时变量，所有变量均在循环内原地更新，降低了内存分配和垃圾回收的负担。

# 长度扩展攻击原理
## 什么是长度扩展攻击？
SM3、MD5、SHA-1、SHA-256 等基于 Merkle-Damgård 结构的哈希算法，存在长度扩展攻击漏洞。
如果 MAC 计算方式为 SM3(key || message)，攻击者可以：
拿到 message 和 MAC=SM3(key||message)
伪造 message || padding || extension，并计算出合法的 MAC'，无需知道 key。
### 攻击流程
已知条件：攻击者知道 message 和 SM3(key||message)，但不知道 key。
目标：伪造 message || padding || extension，并计算出合法的哈希值。
方法：
利用已知哈希值还原 SM3 内部状态。
构造原消息的填充（padding）。
以还原的状态为起点，继续对 extension 进行哈希，得到新的合法哈希值。
## 代码结构与思路
### 1. SM3_Basic
实现了标准的 SM3 哈希算法，包括消息填充、消息扩展、压缩函数等。
提供 hash() 和 hash_hex() 方法。
### 2. SM3_LengthExtensionAttack
实现长度扩展攻击的核心逻辑。
主要方法：
_generate_padding(original_length)：生成与原消息长度对应的填充。
forge_hash(original_hash, original_length, additional_data)：
还原内部状态
构造扩展消息和填充
继续哈希，得到伪造的哈希值和消息后缀
### 3. demonstrate_length_extension_attack
演示完整攻击流程：
服务器端用 SM3(key||message) 计算原始 MAC
攻击者利用已知 MAC 和消息，伪造新消息和 MAC
服务器端验证伪造消息，发现 MAC 合法，攻击成功
