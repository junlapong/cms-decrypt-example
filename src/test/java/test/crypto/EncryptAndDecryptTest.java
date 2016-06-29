package test.crypto;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jcajce.provider.symmetric.DES;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.junit.Test;

public class EncryptAndDecryptTest {

	static {
		// Add security provider
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	//private static final String WORK_DIR = "D:\\git-space\\cms-decrypt-example";
	private static final String WORK_DIR = "/home/junlapong/git-space/cms-decrypt-example";

	private static final File SOURCE_PDF = new File(WORK_DIR, "source.xml");
	private static final File DESTINATION_FILE = new File(WORK_DIR, "encrypted.xml");
	private static final File DECRYPTED_FILE = new File(WORK_DIR, "decrypted.xml");


	@Test
	public void shouldEncryptAndDecrypt() throws Exception {

		if (!new File(WORK_DIR).exists()) {
			throw new RuntimeException("Update WORK_DIR to point to the directory the project is cloned into.");
		}

		Files.deleteIfExists(DESTINATION_FILE.toPath());
		Files.deleteIfExists(DECRYPTED_FILE.toPath());

		X509Certificate certificate = EncryptAndDecrypt.getX509Certificate(new File(WORK_DIR, "certificate.pem"));
		PrivateKey privateKey = EncryptAndDecrypt.getPrivateKey(new File(WORK_DIR, "certificate.p12"), "Qwer12345");

		EncryptAndDecrypt.encrypt(certificate, SOURCE_PDF, DESTINATION_FILE);
		EncryptAndDecrypt.decrypt(privateKey, DESTINATION_FILE, DECRYPTED_FILE);
	}

}
