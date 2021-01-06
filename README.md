# cryptography

The demo of cryptography. The content as follows:
* DRBG random:
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
* SCA Symmetric crypto   **<<<<<----- at present**
* HMAC CCM GCM
* x509 CA


## ECDH reference:
* https://tools.ietf.org/html/rfc7748#page-4
* Weierstrass Curve(secp256r1 etc): 
* Montgomery Curve(curve25519+curve448): https://learnblockchain.cn/article/1641
* Edwards Curve(adwards22519 etc): https://blog.csdn.net/mutourend/article/details/98597316