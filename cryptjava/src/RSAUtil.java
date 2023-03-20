import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {
    static int lengthLine = 64;
    static int bits = 2048;

    public static byte[] base64Encode(byte[] bytesDecoded) {
        return Base64.getEncoder().encode(bytesDecoded);
    }

    public static byte[] base64Decode(byte[] bytesEncoded) {
        return Base64.getDecoder().decode(bytesEncoded);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    public static RSAPrivateKey getPrivateKeyFromPair(KeyPair keyPair) {
        return (RSAPrivateKey) keyPair.getPrivate();
    }

    public static RSAPublicKey getPublicKeyFromPair(KeyPair keyPair) {
        return (RSAPublicKey) keyPair.getPublic();
    }

    public static RSAPrivateKey readPrivateKey(File file) throws Exception {
        String pem = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
        return readPrivateKey(pem);
    }

    public static RSAPrivateKey readPrivateKey(String pem) throws Exception {
        String privateKeyPEM = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replaceAll("\r\n", "")
            .replaceAll("\n", "")
            .replace("-----END PRIVATE KEY-----", "");

        byte[] encodedKey = base64Decode(privateKeyPEM.getBytes());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    public static RSAPublicKey readPublicKey(File file) throws Exception {
        String pem  = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
        return readPublicKey(pem);
    }

    public static RSAPublicKey readPublicKey(String pem) throws Exception {
        String publicKeyPEM = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replaceAll("\r\n", "")
            .replaceAll("\n", "")
            .replace("-----END PUBLIC KEY-----", "");

        byte[] encodedKey = base64Decode(publicKeyPEM.getBytes());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static RSAPublicKey getPublicKeyfromPrivateKey(RSAPublicKey privateKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey privgateCrtKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privgateCrtKey.getModulus(), privgateCrtKey.getPublicExponent());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    public static String getPemStringPrivateKey(RSAPrivateKey rsaPrivateKey) {
        String content = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
        int lengthContent = content.length();
        int countRows = (int) Math.ceil((double)lengthContent / lengthLine);

        String stringPem = "-----BEGIN PRIVATE KEY-----" + "\n";
        for (int ii = 0; ii < countRows; ++ii) {
            if (ii == countRows - 1) {
                stringPem += content.substring(ii * lengthLine) + "\n";
            }
            else {
                stringPem += content.substring(ii * lengthLine, (ii + 1) * lengthLine) + "\n";
            }
        }
        stringPem += "-----END PRIVATE KEY-----";

        return stringPem;
    }

    public static String getPemStringPublicKey(RSAPublicKey rsaPublicKey) {
        String content = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
        int lengthContent = content.length();
        int countRows = (int) Math.ceil((double)lengthContent / lengthLine);

        String stringPem = "-----BEGIN PUBLIC KEY-----" + "\n";
        for (int ii = 0; ii < countRows; ++ii) {
            if (ii == countRows - 1) {
                stringPem += content.substring(ii * lengthLine) + "\n";
            }
            else {
                stringPem += content.substring(ii * lengthLine, (ii + 1) * lengthLine) + "\n";
            }
        }
        stringPem += "-----END PUBLIC KEY-----";

        return stringPem;
    }

    public static String encryptPublic(String plainText, PublicKey publicKey)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytePlain = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(bytePlain);
    }

    public static String decryptPrivate(String encrypted, PrivateKey privateKey)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        return new String(bytePlain, "utf-8");
    }

    public static String encryptPrivate(String plainText, PrivateKey privateKey)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] bytePlain = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(bytePlain);
    }

    public static String decryptPublic(String encrypted, PublicKey publicKey)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        return new String(bytePlain, "utf-8");
    }
}
