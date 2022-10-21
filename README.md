# Cryptography Demo

## 内容说明

本仓库用于存储对于加解密算法学的接口使用，主要使用mbedtls和openssl及一些其他的开源加解密库进行的demo展示，包含以下内容：

* 随机数生成（DRBG）
* Digest（HASH/MD5/SM3/CMAC/HMAC等）
* 对称加密（AES/SM4/KASUMI/GCM/Chacha20）
* 非对称加密（RSA/ECC/SM2）
* 密钥交换
* x509 CA

工程目录如下：

```
├── lib
│   ├── kasumi
│   ├── mbedtls
│   └── openssl
├── modules
│   ├── asym
│   ├── cert
│   ├── common
│   ├── digest
│   ├── random
│   └── sym
├── testsuite
│   ├── inc
│   ├── main.c
│   ├── src
│   └── thirdpart
└── utils
    ├── inc
    └── src
```

本工程由 [CUnit - A Unit testing framework library for C. ](https://cunit.sourceforge.net/)单元测试框架对程序密码学模块进行组织。每一个模块（c文件）相应的嵌入到一个单元测试文件中。由`testsuite/main.c`函数组织注册这些测试文件。

`modules`：为各个密码学模块的封装

`testsuite`：单元测试框架

`utils`：提供一些支持工具的服务

`lib`：引用的第三方密码学库等

**编译系统使用cmake**

## 具体包含

* DRBG random number:
  * 1.1 ctr drbg
  * 1.2 hash drbg
  * 1.3 hmac drbg

* HASH and SHA
  * 2.1 MD5
  * 2.2 SHA224/SHA256/SHA384/SHA512
* ACA Asymmetric crypto
  * 3.1 RSA pkcs#1 en/de
  * 3.2 RSA pkcs#8 en/de
  * 3.3 RSA pkcs#1 sign/verify
  * 3.4 RSA pkcs#8 sign/verify
  * 3.5 ECC en/de
  * 3.6 ECC (ECDSA）
  * 3.7 SM2 en/de
  * 3.8 DH share key
  * 3.9 ECDH share key
* x509 CA
  * 4.1 csr file
  * 4.2 crt file
  * 4.3 ssl com (not finish)
* SCA Symmetric crypto
  * AES
  * Camellia
  * DES/3DES
  * GCM
  * CCM
  * Chacha20

## 编译：

* 需要自行编译mbedtls库和openssl库
* `cmake CmakeLists.txt`
* `make`

## ECDH reference:

* https://tools.ietf.org/html/rfc7748#page-4
* Weierstrass Curve(secp256r1 etc):
* Montgomery Curve(curve25519+curve448): https://learnblockchain.cn/article/1641
* Edwards Curve(adwards22519 etc): https://blog.csdn.net/mutourend/article/details/98597316
* 椭圆曲线的压缩和非压缩秘钥:https://ld246.com/article/1550844562914
* https://blog.wandoer.com/note/%E4%BD%BF%E7%94%A8-openssl-%E8%BF%9B%E8%A1%8C-dh-%E5%AF%86%E9%92%A5%E4%BA%A4%E6%8D%A2.htm
## X509 reference:
https://www.jianshu.com/p/a9497de4cbff
https://www.cnblogs.com/milton/archive/2004/01/13/11076925.html
