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
import java.util.Arrays;
import java.util.Base64;

@ApplicationScoped
public class Util {

    private static final Logger log = LoggerFactory.getLogger(Util.class);

    static String salt = ConfigProvider.getConfig().getValue("salt", String.class);
    static String encKey = ConfigProvider.getConfig().getValue("encKey", String.class);

    public static SecretKey key = getKeyFromPassword(encKey, salt);//generateKey(128);
    public static final String algorithm = "AES/CBC/PKCS5Padding";

    public static String decryptCookieValue(String cookieParameter) throws ForbiddenException {
        String plainText = null;
        try {
            plainText = decrypt(algorithm, cookieParameter, key);

        } catch (Exception e) {
            log.warn(e.getMessage());
            throw new ForbiddenException("Cookie decryption failed");
        }
        return plainText;
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        byte[] b64decodedCipherText = Base64.getDecoder().decode(cipherText);
        byte[] ivRaw = Arrays.copyOfRange(b64decodedCipherText, 0, 16);
        IvParameterSpec iv = new IvParameterSpec(ivRaw);
        byte[] trimmedCipherText = Arrays.copyOfRange(b64decodedCipherText, 16, b64decodedCipherText.length);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(trimmedCipherText);
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
}
