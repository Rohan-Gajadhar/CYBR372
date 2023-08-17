package Part3;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int count = 1000;

    public static void main(String[] args) throws Exception {

        // args[0] determines wether to run in encryption or decryption mode
        try {
            if (args[0].equals("enc")) {
                char[] password = args[1].toCharArray(); // save the password as a char array for extra security
                String inputFile = args[2];
                String outputFile = args[3];
                encryption(password, inputFile, outputFile);
            } else if (args[0].equals("dec")) {
                char[] password = args[1].toCharArray(); // save the password as a char array for extra security
                String inputFile = args[2];
                String outputFile = args[3];
                decryption(password, inputFile, outputFile);
            }
            // if args[0] is not "enc" or "dec", print error message
            else {
                System.out.println("Invalid mode, please use 'enc' or 'dec'");
            }
            // catch all other exceptions and prints blanket error message
        } catch (Exception e) {
            if (args[0].equals("enc")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part3/FileEncryptor.java <mode> <password> <inputFile> <outputFile>"
                                + e);
            } else if (args[0].equals("dec")) {
                System.out.println(
                        "Invalid arguments, use the format: java Part3/FileEncryptor.java <mode> <password> <inputFile> <outputFile>");
            }
        }
    }

    // create secret key using password and salt
    public static SecretKey createSecretKey(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKey pbeKey = null;
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, count, 256); // define key specs
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // hashing algorithm
            pbeKey = new SecretKeySpec(keyFac.generateSecret(pbeKeySpec).getEncoded(), ALGORITHM); // create key
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Unable to generate secret key, invalid algorithm");
        } catch (InvalidKeySpecException e) {
            System.out.println("Unable to generate secret key, invalid key spec");
        }
        return pbeKey;
    }

    public static void encryption(char[] password, String inputFile, String outputFile) throws Exception {

        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt); // generate 128 bit salt using SecureRandom
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // generate 128 iv using SecureRandom
        IvParameterSpec iv = new IvParameterSpec(initVector);

        // create the secret key using password and salt and print for marking purposes
        SecretKey skey = createSecretKey(password, salt);
        System.out.println("Secret Key: " + Base64.getEncoder().encodeToString(skey.getEncoded()));

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skey, iv);

        final Path encryptedPath = Paths.get("Part3", outputFile); // encrypted filepath
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inputFile);
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                }) {
            final byte[] bytes = new byte[1024];
            // add the salt and iv to the start of the encrypted file
            fout.write(salt);
            fout.write(initVector);
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryption(char[] password, String inputFile, String outputFile) throws Exception {
        
        byte[] salt = new byte[16]; // create byte array to store iv from first 16 bytes of ciphertext
        byte[] ciphertextIV = new byte[16]; // create byte array to store salt from next 16 bytes of ciphertext

        // encrypted and decrypted filepaths
        final Path encryptedPath = Paths.get("Part3", inputFile);
        final Path decryptedPath = Paths.get("Part3", outputFile);

        try (InputStream encryptedData = Files.newInputStream(encryptedPath)) {
            encryptedData.read(salt); // read the first 16 bytes of the ciphertext to obtain the salt
            encryptedData.read(ciphertextIV); // read the next 16 bytes of the ciphertext to obtain the iv

            IvParameterSpec iv = new IvParameterSpec(ciphertextIV);
            SecretKey skey = createSecretKey(password, salt); // create the secret key using the password and salt

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
