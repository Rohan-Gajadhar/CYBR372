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

    public static byte[] encryption(byte[] data, PublicKey publicKey) throws Exception {
        System.out.println("Server sending cleartext: " + new String(data, "UTF-8"));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        data = cipher.doFinal(data);
        System.out.println("Server sending ciphertext: " + Util.bytesToHex(data));
        return data;
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static byte[] concatenateDataAndSignature(byte[] data, byte[] signature) {
        byte[] message = new byte[data.length + signature.length];
        System.arraycopy(data, 0, message, 0, data.length);
        System.arraycopy(signature, 0, message, data.length, signature.length);
        return message;
    }


    public byte[] decrypt(byte[] message, PrivateKey privateKey) throws Exception {
        System.out.println("\nServer returned ciphertext: " + Util.bytesToHex(message));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        message = cipher.doFinal(message);
        System.out.println("Server returned cleartext: " + new String(message, "UTF-8"));
        return message;
    }

    public void verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message);
        boolean verified = sig.verify(signature);
        if (verified) {
            System.out.println("\nSignature was verified!");
        } else {
            System.out.println("\nSignature was unable to be verified.");
        }
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws Exception{
            KeyPair encryptDecryptKP = keyPairGeneration("Server Encrypt/Decrypt");
            KeyPair signatureKP = keyPairGeneration("Server Signature");

            //save server keys to file
            saveKeyPair(encryptDecryptKP, "EncryptDecrypt");
            saveKeyPair(signatureKP, "Signature");

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());

            // decrypt data
            byte[] receivingData = new byte[512];
            byte[] message = new byte[256];
            byte[] clientSignature = new byte[256];
            int numBytes;

            while ((numBytes = in.read(receivingData)) != -1) {
                //load client keys from file
                KeyPair clientEncryptDecryptKP = loadKeyPair("EncryptDecrypt");
                KeyPair clientSignatureKP = loadKeyPair("Signature");
                //decrypt data
                System.arraycopy(receivingData, 0, message, 0, 256);
                System.arraycopy(receivingData, 256, clientSignature, 0, 256);
                byte[] sendingData = decrypt(message, encryptDecryptKP.getPrivate());
                verifySignature(message, clientSignature, clientSignatureKP.getPublic());

                sendingData = encryption(sendingData, clientEncryptDecryptKP.getPublic());
                byte[] serverSignature = sign(sendingData, signatureKP.getPrivate());
                sendingData = concatenateDataAndSignature(sendingData, serverSignature);
                out.write(sendingData);
                out.flush();
            }
            stop();
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



    public static void main(String[] args) throws Exception{
        EchoServer server = new EchoServer();
        server.start(4444);
    }

}



