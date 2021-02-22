# Cryptography Demo

The demo of cryptography. Haochen mate's reinvent the wheel. 

The content as follows:

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
* x509 CA          **<<<<<----- at present**
* SCA Symmetric crypto
* HMAC CCM GCM


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
