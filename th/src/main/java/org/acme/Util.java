package org.acme;

import org.acme.exceptions.ForbiddenException;
import org.acme.exceptions.UnauthorizedException;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@ApplicationScoped
public class Util {

    static String salt = ConfigProvider.getConfig().getValue("salt", String.class);
    static String encKey = ConfigProvider.getConfig().getValue("encKey", String.class);
    static String ivKey = ConfigProvider.getConfig().getValue("ivKey", String.class);

    private static final Logger log = LoggerFactory.getLogger(Util.class);

    // FIXME - These need to persisted and shared
    public static SecretKey key = getKeyFromPassword(encKey, salt);//generateKey(128);
    public static IvParameterSpec ivParameterSpec = new IvParameterSpec(ivKey.getBytes(Charset.forName("UTF8")));//generateIv();
    public static final String algorithm = "AES/CBC/PKCS5Padding";

    public static String getCodeChallenge(String password) {
        String encodedContent = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
            encodedContent = encoder.encodeToString(hashInBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return encodedContent;
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

    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
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

    public static SecretKey generateKey(int n) {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static String generateRandomString(int length) throws NoSuchAlgorithmException {
        final String chrs = "0123456789abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        return secureRandom.ints(length, 0, chrs.length()).mapToObj(i -> chrs.charAt(i))
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
    }

    public static String encryptCookieValue(String value) {
        String cipherText = null;
        try {
            cipherText = encrypt(algorithm, value, key, ivParameterSpec);

        } catch (Exception e) {
            log.warn(e.getMessage());
            throw new ForbiddenException("Cookie encryption failed");
        }
        return cipherText;
    }

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

}
