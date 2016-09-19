import java.util.UUID;
import org.junit.Test;
import org.apache.commons.codec.digest.DigestUtils;

public class MessageDigestTest {

    @Test
    public void shouldPrintUuid() throws Exception {

        UUID uuid = UUID.randomUUID();
        System.out.println("uuid: " + uuid);
    }

    @Test
    public void shouldPrintHash() throws Exception {

        String md5 = DigestUtils.md5Hex("TEST md5");
        System.out.println("md5: " + md5);

        String sha1 = DigestUtils.sha1Hex("TEST sha1");
        System.out.println("sha1: " + sha1);

        String sha256 = DigestUtils.sha256Hex("TEST sha256");
        System.out.println("sha256: " + sha256);
    }

}
