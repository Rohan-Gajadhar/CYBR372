package Part1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
//import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws Exception {

        // args[0] determines wether to run in encryption or decryption mode
        try{
            if(args[0].equals("enc")){
                String inputFile = args[1];
                String outputFile = args[2];
                encryption(inputFile, outputFile);
            }
            else if(args[0].equals("dec")){
                String base64SecretKey = args[1];
                String base64IV = args[2];
                String inputFile = args[3];
                String outputFile = args[4];
                decryption(base64SecretKey, base64IV, inputFile, outputFile);
            }
            // if args[0] is not "enc" or "dec", print error message
            else{
                System.out.println("Invalid mode, please use 'enc' or 'dec'");
            }
        // catch all other exceptions and prints blanket error message
        } catch (Exception e){
            if(args[0].equals("enc")) {
                System.out.println("Invalid arguments, use the format: java Part1/FileEncryptor.java <mode> <inputFile> <outputFile>");
            }
            else if(args[0].equals("dec")) {
                System.out.println("Invalid arguments, use the format: java Part1/FileEncryptor.java <mode> <base64SecretKey> <base64IV> <inputFile> <outputFile>");
            }
        }
    }

    public static void encryption(String inputFile, String outputFile) throws Exception {
        SecureRandom sr = new SecureRandom(); // SecureRandom is a cryptographically strong random number generator, instead of 'java.lang.Random'
        byte[] key = new byte[16]; //create 16 byte, byte array to hold key
        sr.nextBytes(key); // generate a 128 bit key using SecureRandom
        byte[] initVector = new byte[16]; //create 16 byte, byte array to hold
        sr.nextBytes(initVector); // generate a 128 bit IV using SecureRandom
        IvParameterSpec iv = new IvParameterSpec(initVector); // create IvParameterSpec object using iv byte array to be used in cipher encryption intialisation
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM); // create SecretKeySpec object using key byte array to be used in cipher encryption intialisation
        Cipher cipher = Cipher.getInstance(CIPHER); // create Cipher object using the specified cipher algorithm
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // intialize cipher in encryption mode with the specified key and IV
        
        final Path encryptedPath = Paths.get("Part1", outputFile); // path to the encrypted file after encryption
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inputFile); // locates input file eg: plaintext.txt
                OutputStream fout = Files.newOutputStream(encryptedPath); // creates and writes to output file eg: ciphertext.enc
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) { // encrypts data before writing to output file
        }) {
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        // print secret key and iv after try block to ensure they are not printed if an exception is thrown
        System.out.println("Secret key is: " + Base64.getEncoder().encodeToString(key)); // encodes the key to a string using Base64 encoding
        System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector)); // encodes the IV to a string using Base64 encoding
        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryption(String base64SecretKey, String base64IV, String inputFile, String outputFile) throws Exception {
        byte [] base64key = Base64.getDecoder().decode(base64SecretKey); //decode base64 encoded key to byte array
        byte [] base64iv = Base64.getDecoder().decode(base64IV); //decode base64 encoded IV to byte array

        SecretKeySpec skey = new SecretKeySpec(base64key, ALGORITHM); // creates SecretKeySpec object using key byte array to be used in cipher decryption intialisation
        IvParameterSpec iv = new IvParameterSpec(base64iv); // create IvParameterSpec object using iv byte array to be used in cipher decryption intialisation

        Cipher cipher = Cipher.getInstance(CIPHER); // create Cipher object using the specified cipher algorithm
        cipher.init(Cipher.DECRYPT_MODE, skey, iv); // intialize cipher in decryption mode with the specified key and IV

        final Path encryptedPath = Paths.get("Part1", inputFile);
        final Path decryptedPath = Paths.get("Part1", outputFile);
        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        
        LOG.info("Decryption complete, open " + decryptedPath);
    }

}
