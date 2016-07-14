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
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
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

	private static final File SOURCE_PDF = new File(WORK_DIR, "source.xml");
	private static final File DESTINATION_FILE = new File(WORK_DIR, "encrypted.xml");
	private static final File DECRYPTED_FILE = new File(WORK_DIR, "decrypted.xml");

	public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

	@Test
	@Ignore
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

	@Test
	public void shouldEncryptDecryptMessage() throws Exception {

		X509Certificate publicCert = EncryptAndDecrypt.getX509Certificate(new File(WORK_DIR, "certificate.pem"));		
		String encryptedMessage = encryptMessage("<XML>", publicCert);
		
		PrivateKey privateKey = EncryptAndDecrypt.getPrivateKey(new File(WORK_DIR, "certificate.p12"), "Qwer12345");
		// decryptMessage(encryptedMessage, privateKey);
		
	}
	
	public static String encryptMessage(String message, X509Certificate cert) throws CertificateEncodingException, CMSException, IOException {

		CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
		generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
		
		OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

		ByteArrayOutputStream signedData = new ByteArrayOutputStream();
		OutputStream encryptingStream = generator.open(signedData, encryptor);

		encryptingStream.write(message.getBytes("UTF-8"));			
		String encryptedMessage = new String(Base64.encode(signedData.toByteArray()), "UTF-8");
		
		System.out.println(encryptedMessage);
		
		return encryptedMessage;

	}
	
	public static void decryptMessage(String encryptedMessage, PrivateKey privateKey) throws IOException, CMSException {

		byte[] encryptedData = encryptedMessage.getBytes("UTF-8");

		CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedData);

		RecipientInformation recInfo = getSingleRecipient(parser);
		Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
		
//		ByteArrayInputStream decryptedStream = (ByteArrayInputStream) recInfo.getContentStream(recipient).getContentStream();

	}

	private static RecipientInformation getSingleRecipient(CMSEnvelopedDataParser parser) {
		Collection<RecipientInformation> recInfos = parser.getRecipientInfos().getRecipients();
		Iterator<RecipientInformation> recipientIterator = recInfos.iterator();
		if (!recipientIterator.hasNext()) {
			throw new RuntimeException("Could not find recipient");
		}
		return (RecipientInformation) recipientIterator.next();
	}

}
