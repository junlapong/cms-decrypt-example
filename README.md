# cms-decrypt-example

 - `certificate.pem` - certificate (public key) used for encryption
 - `certificate.p12` - private key used for decryption

## Notes
 - [Error Java Security: Illegal key size](http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters)
 - [How to install Java Cryptography Extension unlimited strength jurisdiction policy files](http://opensourceforgeeks.blogspot.in/2014/09/how-to-install-java-cryptography.html)

## Download JCE
  - [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 6 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)
  - [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 7 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
  - [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8 Download](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)

  install the files `local_policy.jar` and `US_export_policy.jar` in /path/to/jre/lib/security/

  ```
  [Linux]
  /usr/lib/jvm/java-8-oracle/jre/lib/security

  [Windows]
  D:\Java\jdk8_x64\jre\lib\security
  ```
