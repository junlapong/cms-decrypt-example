package test.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Ignore;
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

	private static final File SOURCE_FILE = new File(WORK_DIR, "source.xml");
	private static final File DESTINATION_FILE = new File(WORK_DIR, "encrypted.xml");
	private static final File DECRYPTED_FILE = new File(WORK_DIR, "decrypted.xml");

	public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

	@Test
	public void shouldEncryptAndDecryptFile() throws Exception {

		if (!new File(WORK_DIR).exists()) {
			throw new RuntimeException("Update WORK_DIR to point to the directory the project is cloned into.");
		}

		Files.deleteIfExists(DESTINATION_FILE.toPath());
		Files.deleteIfExists(DECRYPTED_FILE.toPath());

		X509Certificate certificate = EncryptAndDecrypt.getX509Certificate(new File(WORK_DIR, "certificate.pem"));
		PrivateKey privateKey = EncryptAndDecrypt.getPrivateKey(new File(WORK_DIR, "certificate.p12"), "Qwer12345");

		EncryptAndDecrypt.encrypt(certificate, SOURCE_FILE, DESTINATION_FILE);
		EncryptAndDecrypt.decrypt(privateKey, DESTINATION_FILE, DECRYPTED_FILE);
	}

	@Test
	public void shouldEncryptAndDecryptMessage() throws Exception {

		X509Certificate certificate = EncryptAndDecrypt.getX509Certificate(new File(WORK_DIR, "certificate.pem"));
		String encryptedMessage = encryptMessage("<InitRequest></InitRequest>", certificate);
		System.out.println(encryptedMessage);

		PrivateKey privateKey = EncryptAndDecrypt.getPrivateKey(new File(WORK_DIR, "certificate.p12"), "Qwer12345");
		String decryptedMessage = decryptMessage(encryptedMessage, privateKey);
		System.out.println(decryptedMessage);
	}

	public static String encryptMessage(String message, X509Certificate cert) throws Exception {

		// create CMS envelope data;
		// check http://www.ietf.org/rfc/rfc3852.txt pages 15-16 for details
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
		gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));

		OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CMSTypedData content = new CMSProcessableByteArray(message.getBytes("UTF-8"));
		CMSEnvelopedData data = gen.generate(content, encryptor);
		String encryptedMessage = new String(Base64.encode(data.getEncoded()));

		return encryptedMessage;
	}

	public static String decryptMessage(String encryptedMessage, PrivateKey privateKey) throws Exception {

		byte[] encryptedData = Base64.decode(encryptedMessage);

		// parse CMS envelope data
		CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedData);

		Collection<RecipientInformation> recInfos = parser.getRecipientInfos().getRecipients();
		Iterator<RecipientInformation> recipientIterator = recInfos.iterator();

		if (! recipientIterator.hasNext()) {
			throw new RuntimeException("Could not find recipient");
		}

		// retrieve recipient and decode it
		RecipientInformation recInfo = (RecipientInformation) recipientIterator.next();
		Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
		byte[] decryptedData = recInfo.getContent(recipient);

		return new String(decryptedData);
	}

}
