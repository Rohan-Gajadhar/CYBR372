import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.security.*;
import java.io.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    public static KeyPair keyPairGeneration(String keyPairName) throws NoSuchAlgorithmException{
        //user enters desired key length
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter a key length (eg: 1024, 2048, 4096)");
        int keyLength = scan.nextInt();
        //scan.close();

        //generate key pair
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        KeyPair key = keyGen.generateKeyPair();

        //get public and private keys
        final PublicKey publicKey = key.getPublic();
        final PrivateKey privateKey = key.getPrivate();

        //print public key
        System.out.println("\n" + keyPairName + " Public Key:\n" + publicKey + "\n");
        System.out.println(keyPairName + " Public Key:\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");

        return key;
    }

    public static void saveKeyPair(KeyPair kp, String keyPairName){
        //encode public and private keys
        X509EncodedKeySpec encodedPublicKey = new X509EncodedKeySpec(kp.getPublic().getEncoded());
        PKCS8EncodedKeySpec encodedPrivateKey = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        try {
            //write public key to file
            FileOutputStream fos = new FileOutputStream("Assignment2/" + keyPairName + "ServerPublicKey.key");
            fos.write(encodedPublicKey.getEncoded());
            fos.close();

            //write private key to file
            fos = new FileOutputStream("Assignment2/" + keyPairName + "ServerPrivateKey.key");
            fos.write(encodedPrivateKey.getEncoded());
            fos.close();

        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public static KeyPair loadKeyPair(String keyPairName) throws Exception{
        //read client public key from file
        File filePublicKey = new File("Assignment2/" + keyPairName +  "ClientPublicKey.key");
        FileInputStream fis = new FileInputStream("Assignment2/" + keyPairName +  "ClientPublicKey.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        //read private key
        File filePrivateKey = new File("Assignment2/" + keyPairName +  "ClientPrivateKey.key");
        fis = new FileInputStream("Assignment2/" + keyPairName +  "ClientPrivateKey.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        //create public key spec from file
        //???
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        //create private key spec from file
        //???
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            KeyPair encryptDecryptKP = keyPairGeneration("Server Encrypt/Decrypt");
            KeyPair signatureKP = keyPairGeneration("Server Signature");

            //save server keys to file
            saveKeyPair(encryptDecryptKP, "EncryptDecrypt");
            saveKeyPair(signatureKP, "Signature");

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());



            byte[] data = new byte[512]; //to hold all received data
            byte[] ciphertext = new byte[256]; //to hold the ciphertext
            byte[] verifySignature = new byte[256]; //to hold the signature
            Cipher cipher = Cipher.getInstance(CIPHER);

            int numBytes;
            while ((numBytes = in.read(data)) != -1) {
                //load client keys from file
                KeyPair clientEncryptDecryptKP = loadKeyPair("EncryptDecrypt");
                KeyPair clientSignatureKP = loadKeyPair("Signature");

                //splits data into ciphertext and signature arrays
                System.arraycopy(data, 0, ciphertext, 0, 256);
                System.arraycopy(data, 256, verifySignature, 0, 256);
                System.out.println("Server received ciphertext: "+Util.bytesToHex(ciphertext));
                //decrypt data
                cipher.init(Cipher.DECRYPT_MODE, encryptDecryptKP.getPrivate());
                byte[] decryptedCiphertext = cipher.doFinal(ciphertext);
                String msg = new String(decryptedCiphertext, "UTF-8");
                System.out.println("Server received cleartext: "+msg);

                //verify signature
                Signature verifySig = Signature.getInstance(SIGNATURE_ALGORITHM);
                verifySig.initVerify(clientSignatureKP.getPublic());
                verifySig.update(ciphertext);
                boolean verified = verifySig.verify(verifySignature);
                if(verified){System.out.println("\nSignature was verified!");}
                else{System.out.println("\nSignature was unable to be verified.");}


                // encrypt response (this is just the decrypted data re-encrypted)
                System.out.println("\nServer sending cleartext: "+msg);
                cipher.init(Cipher.ENCRYPT_MODE, clientEncryptDecryptKP.getPublic());
                data = cipher.doFinal(decryptedCiphertext);
                System.out.println("Server sending ciphertext: "+Util.bytesToHex(data));

                //sign message
                Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
                sig.initSign(signatureKP.getPrivate());
                sig.update(data);
                byte[] signature = sig.sign();
                byte[] combined = new byte[data.length + signature.length];
                System.arraycopy(data, 0, combined, 0, data.length);
                System.arraycopy(signature, 0, combined, data.length, signature.length);
                out.write(combined);
                out.flush();
            }
            stop();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }



    public static void main(String[] args){
        EchoServer server = new EchoServer();
        server.start(4444);
    }

}



