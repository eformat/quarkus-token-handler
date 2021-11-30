package org.acme;

import org.acme.exception.ForbiddenException;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@ApplicationScoped
public class Util {

    private static final Logger log = LoggerFactory.getLogger(Util.class);

    static String salt = ConfigProvider.getConfig().getValue("salt", String.class);
    static String encKey = ConfigProvider.getConfig().getValue("encKey", String.class);
    static String ivKey = ConfigProvider.getConfig().getValue("ivKey", String.class);

    public static SecretKey key = getKeyFromPassword(encKey, salt);//generateKey(128);
    public static IvParameterSpec ivParameterSpec = new IvParameterSpec(ivKey.getBytes(Charset.forName("UTF8")));//generateIv();
    public static final String algorithm = "AES/CBC/PKCS5Padding";

    public static String decryptCookieValue(String cookieParameter) throws ForbiddenException {
        String plainText = null;
        try {
            plainText = decrypt(algorithm, cookieParameter, key, ivParameterSpec);

        } catch (Exception e) {
            log.warn(e.getMessage());
            throw new ForbiddenException("Cookie decryption failed");
        }
        return plainText;
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static SecretKey getKeyFromPassword(String password, String salt) {
        SecretKey secret = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            secret = new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
