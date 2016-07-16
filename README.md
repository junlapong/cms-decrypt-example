# CMS (PKCS#7) Java Example

[RFC-2315 PKCS #7: Cryptographic Message Syntax Version 1.5](https://tools.ietf.org/html/rfc2315)

## Certificate

- `certificate.pem` - certificate (public key) used for encryption
- `certificate.p12` - private key used for decryption

### create keystore
```
keytool -genkey -alias aliasname -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore keystore.p12 -validity 3650 -dname "CN=CNNAME, OU=OU, O=O, L=Bangkok, ST=Bangkok, C=TH"
keytool -list -v -storetype pkcs12 -keystore keystore.p12
```

### export public key
```
### PEM (ASCII) ###
keytool -exportcert -alias itmxlss025 -storetype PKCS12 -keystore keystore.p12 -rfc -file public-key.PEM.cer

### DER (BINARY) ###
keytool -exportcert -alias itmxlss025 -storetype PKCS12 -keystore keystore.p12 -file public-key.DER.cer
```

## Notes
 - [Error Java Security: Illegal key size](http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters)
 - [How to install Java Cryptography Extension unlimited strength jurisdiction policy files](http://opensourceforgeeks.blogspot.in/2014/09/how-to-install-java-cryptography.html)

## Download

JCE Unlimited Strength Jurisdiction Policy Files

  - [Java 6 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)
  - [Java 7 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
  - [Java 8 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)

install files `local_policy.jar` and `US_export_policy.jar` in `${java.home}/jre/lib/security/`

```
[Linux]
/usr/lib/jvm/java-8-oracle/jre/lib/security

[Windows]
C:\path\to\jdk8\jre\lib\security
```
