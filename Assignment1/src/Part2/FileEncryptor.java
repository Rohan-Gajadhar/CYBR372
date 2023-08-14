package Part2;

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

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String mode = args[0];

        // args[0] determines wether to run in encryption or decryption mode
        try{
            if(mode.equals("enc")){
                String b64SKey = args[1];
                String inputFile = args[2];
                String outputFile = args[3];
                encryption(b64SKey, inputFile, outputFile);
            }
            else if(mode.equals("dec")){
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
        } catch (Exception e){
            System.out.println("Invalid arguments" + e);
        }
    }

    //skey for testing: LDtaZzoKrjAldoqUn473DA==

    public static void encryption(String skey, String inputFile, String outputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        SecureRandom sr = new SecureRandom();

        byte[] key = new byte[16];
        key = Base64.getDecoder().decode(skey); //decode the user specified base64 key to byte array

        byte[] initVector = new byte[16]; 
        sr.nextBytes(initVector);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        System.out.println("initVector: " + initVector); //print the IV to the console
        System.out.println("IVParamSpec: " + iv.toString());
        System.out.println("for testing, secret key: " + skey);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        
        final Path encryptedPath = Paths.get(outputFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inputFile);
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) { 
        }) {
            final byte[] bytes = new byte[1024];
            //add the iv to the start of the encrypted file
            fout.write(initVector);
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        
        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryption(String base64SecretKey, String base64IV, String inputFile, String outputFile) throws Exception {
        byte [] base64key = Base64.getDecoder().decode(base64SecretKey); //decode base64 encoded key to byte array
        byte [] base64iv = Base64.getDecoder().decode(base64IV); //decode base64 encoded IV to byte array

        SecretKeySpec skey = new SecretKeySpec(base64key, ALGORITHM); // creates SecretKeySpec object using key byte array to be used in cipher decryption intialisation
        IvParameterSpec iv = new IvParameterSpec(base64iv); // create IvParameterSpec object using iv byte array to be used in cipher decryption intialisation

        Cipher cipher = Cipher.getInstance(CIPHER); // create Cipher object using the specified cipher algorithm
        cipher.init(Cipher.DECRYPT_MODE, skey, iv); // intialize cipher in decryption mode with the specified key and IV

        final Path encryptedPath = Paths.get(inputFile);
        final Path decryptedPath = Paths.get(outputFile);
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

