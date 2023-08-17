package Part1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws Exception {

        // args[0] determines wether to run in encryption or decryption mode
        try {
            if (args[0].equals("enc")) {
                String inputFile = args[1];
                String outputFile = args[2];
                encryption(inputFile, outputFile);
            } else if (args[0].equals("dec")) {
                String base64SecretKey = args[1];
                String base64IV = args[2];
                String inputFile = args[3];
                String outputFile = args[4];
                decryption(base64SecretKey, base64IV, inputFile, outputFile);
            }
            // if args[0] is not "enc" or "dec", print error message
            else {
                System.out.println("Invalid mode, please use 'enc' or 'dec'");
            }
            // catch all other exceptions and prints blanket error message
        } catch (Exception e) {
            if (args[0].equals("enc")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part1/FileEncryptor.java <mode> <inputFile> <outputFile>");
            } else if (args[0].equals("dec")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part1/FileEncryptor.java <mode> <base64SecretKey> <base64IV> <inputFile> <outputFile>");
            }
        }
    }

    public static void encryption(String inputFile, String outputFile) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // generate a 128 bit key using SecureRandom
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // generate a 128 bit iv using SecureRandom

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        final Path encryptedPath = Paths.get("Part1", outputFile); // encrypted file filepath
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inputFile);
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                }) {
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        // print secret key and iv
        System.out.println("Secret key is: " + Base64.getEncoder().encodeToString(key));
        System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector));
        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryption(String base64SecretKey, String base64IV, String inputFile, String outputFile)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IOException {
                
        byte[] base64key = Base64.getDecoder().decode(base64SecretKey);
        byte[] base64iv = Base64.getDecoder().decode(base64IV);

        SecretKeySpec skey = new SecretKeySpec(base64key, ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(base64iv);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skey, iv);

        final Path encryptedPath = Paths.get("Part1", inputFile); // encrypted filepath
        final Path decryptedPath = Paths.get("Part1", outputFile); // decrypted filepath
        try (InputStream encryptedData = Files.newInputStream(encryptedPath);
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", e);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

}
