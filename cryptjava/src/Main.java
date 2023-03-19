import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Main {
    public static void printUsage()
    {
        System.out.println("Usage) java -jar cryptJava encryptPublic public.pem plain");
        System.out.println("       java -jar cryptJava decryptPrivate private.pem crypt");
        System.out.println("       java -jar cryptJava encryptPrivate private.pem plain");
        System.out.println("       java -jar cryptJava decryptPublic public.pem crypt");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            printUsage();
            return;
        }

        for (int ii = 0 ; ii < args.length; ++ii) {
            System.out.println("args[" + ii + "] : " + args[ii]);
        }
        System.out.println();

        if (args[0].equals("encryptPublic")) {
            File publicFile = new File(args[1]);
            RSAPublicKey publicKey =  RSAUtil.readPublicKey(publicFile);
            String encryptedMessage = RSAUtil.encryptPublic(args[2], publicKey);
            System.out.println("Encrypted Message : [" + encryptedMessage + "]");
        }
        else if (args[0].equals("decryptPrivate")) {
            File privateFile = new File(args[1]);
            RSAPrivateKey privateKey =  RSAUtil.readPrivateKey(privateFile);
            String decryptedMessage = RSAUtil.decryptPrivate(args[2], privateKey);
            System.out.println("Decrypted Message : [" + decryptedMessage + "]");
        }
        else if (args[0].equals("encryptPrivate")) {
            File privateFile = new File(args[1]);
            RSAPrivateKey privateKey =  RSAUtil.readPrivateKey(privateFile);
            String encryptedMessage = RSAUtil.encryptPrivate(args[2], privateKey);
            System.out.println("Encrypted Message : [" + encryptedMessage + "]");
        }
        else if (args[0].equals("decryptPublic")) {
            File publicFile = new File(args[1]);
            RSAPublicKey publicKey =  RSAUtil.readPublicKey(publicFile);
            String decryptedMessage = RSAUtil.decryptPublic(args[2], publicKey);
            System.out.println("Decrypted Message : [" + decryptedMessage + "]");
        }
        else {
            printUsage();
            return;
        }
    }
}
