package test;

import java.util.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertStore;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.SystemUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cms.*;

public class PKCS7Example {

    private PrivateKey privateKey;
    private String alias;

    public KeyStore getKeystore(char[] password) throws GeneralSecurityException, IOException {
        KeyStore keystore = KeyStore.getInstance("jks");
        InputStream input = new FileInputStream(SystemUtils.USER_HOME + File.separator + ".keystore");
        try {
            keystore.load(input, password);
        } catch (IOException e) {
        } finally {
            IOUtils.closeQuietly(input);
        }
        return keystore;
    }

    public byte[] sign(byte[] data) throws GeneralSecurityException, CMSException, IOException {

        Security.addProvider(new BouncyCastleProvider());

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSigner(getPrivateKey(), (X509Certificate) getCertificate(),
        CMSSignedDataGenerator.DIGEST_SHA1);
        generator.addCertificatesAndCRLs(getCertStore());
        CMSProcessable content = new CMSProcessableByteArray(data);
        CMSSignedData signedData = generator.generate(content, true, "BC");

        return signedData.getEncoded();
    }

    public byte[] design(byte[] signedBytes) throws GeneralSecurityException, CMSException, IOException {

        CMSSignedData s = new CMSSignedData(signedBytes);
        CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");
        SignerInformationStore signers = s.getSignerInfos();
        boolean verified = false;

        for (Iterator i = signers.getSigners().iterator(); i.hasNext(); ) {
            SignerInformation signer = (SignerInformation) i.next();
            Collection<? extends Certificate> certCollection = certs.getCertificates(signer.getSID());

            if (!certCollection.isEmpty()) {
                X509Certificate cert = (X509Certificate) certCollection.iterator().next();
                if (signer.verify(cert.getPublicKey(), "BC")) {
                    verified = true;
                }
            }
        }

        CMSProcessable signedContent = s.getSignedContent() ;
        byte[] originalContent  = (byte[]) signedContent.getContent();

        return originalContent;
    }

    private CertStore getCertStore() throws GeneralSecurityException {
        ArrayList<Certificate> list = new ArrayList<Certificate>();
        Certificate[] certificates = getKeystore("P@ssw0rd".toCharArray()).getCertificateChain(this.alias);
        for (int i = 0, length = certificates == null ? 0 : certificates.length; i < length; i++) {
            list.add(certificates[i]);
        }
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(list), "BC");
    }

    private PrivateKey getPrivateKey() throws GeneralSecurityException {
        if (this.privateKey == null) {
            this.privateKey = initalizePrivateKey();
        }
        return this.privateKey;
    }

    private PrivateKey initalizePrivateKey() throws GeneralSecurityException {
        KeyStore keystore = getKeystore("P@ssw0rd".toCharArray());
        return (PrivateKey) keystore.getKey(this.alias, "P@ssw0rd".toCharArray());
    }

    public X509Certificate getCertificate() {
        return null;
    }
}
