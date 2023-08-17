package Part2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
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
                String b64SKey = args[1];
                String inputFile = args[2];
                String outputFile = args[3];
                encryption(b64SKey, inputFile, outputFile);
            } else if (args[0].equals("dec")) {
                String base64SecretKey = args[1];
                String inputFile = args[2];
                String outputFile = args[3];
                decryption(base64SecretKey, inputFile, outputFile);
            }
            // if args[0] is not "enc" or "dec", print error message
            else {
                System.out.println("Invalid mode, please use 'enc' or 'dec'");
            }
            // catch all other exceptions and prints blanket error message
        } catch (Exception e) {
            if (args[0].equals("enc")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part2/FileEncryptor.java <mode> <base64SecretKey> <inputFile> <outputFile>");
            } else if (args[0].equals("dec")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part2/FileEncryptor.java <mode> <base64SecretKey> <inputFile> <outputFile>");
            }
        }
    }

    // base64 secret key for testing: LDtaZzoKrjAldoqUn473DA==

    public static void encryption(String skey, String inputFile, String outputFile) throws Exception {

        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        key = Base64.getDecoder().decode(skey); // decode the user specified base64 key to byte array

        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // generate a 128 bit iv using SecureRandom

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        final Path encryptedPath = Paths.get("Part2", outputFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inputFile);
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                }) {
            final byte[] bytes = new byte[1024];
            fout.write(initVector); // add the iv to the start of the encrypted file
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryption(String base64SecretKey, String inputFile, String outputFile) throws Exception {
        
        byte[] base64key = Base64.getDecoder().decode(base64SecretKey); // decode the user specified base64 key to byte array
        byte[] ciphertextIV = new byte[16]; // create byte array to store iv from first 16 bytes of the ciphertext

        // encrypted and decrypted filepaths
        final Path encryptedPath = Paths.get("Part2", inputFile);
        final Path decryptedPath = Paths.get("Part2", outputFile);

        try (InputStream encryptedData = Files.newInputStream(encryptedPath)) {
            encryptedData.read(ciphertextIV); // read the first 16 bytes of the ciphertext to obtain iv

            IvParameterSpec iv = new IvParameterSpec(ciphertextIV);
            SecretKeySpec skey = new SecretKeySpec(base64key, ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skey, iv);
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                    OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

            LOG.info("Decryption complete, open " + decryptedPath);
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to decrypt", e);
        }
    }
}
