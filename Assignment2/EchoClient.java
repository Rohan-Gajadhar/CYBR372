import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    public static KeyPair keyPairGeneration(String keyPairName) throws NoSuchAlgorithmException{
        //user enters desired key length
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter a key length (eg: 1024, 2048, 4096)");
        int keyLength = scan.nextInt();

        //generate key pair
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        KeyPair key = keyGen.generateKeyPair();

        //get public and private keys
        final PublicKey publicKey = key.getPublic();

        //print public key
        System.out.println("\n" + keyPairName + " Public Key:\n" + publicKey + "\n");
        System.out.println(keyPairName + " Public Key:\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");

        return key;
    }

    public static void saveKeyPair(KeyPair kp, String keyPairName){
        //save keys to file
        X509EncodedKeySpec encodedPublicKey = new X509EncodedKeySpec(kp.getPublic().getEncoded());
        PKCS8EncodedKeySpec encodedPrivateKey = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
        try {
            //write public key
            FileOutputStream fos = new FileOutputStream("Assignment2/" + keyPairName + "ClientPublicKey.key");
            fos.write(encodedPublicKey.getEncoded());
            fos.close();

            //write private key
            fos = new FileOutputStream("Assignment2/" + keyPairName + "ClientPrivateKey.key");
            fos.write(encodedPrivateKey.getEncoded());
            fos.close();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public static KeyPair loadKeyPair(String keyPairName) throws Exception{
        //read public key
        File filePublicKey = new File("Assignment2/" + keyPairName +  "ServerPublicKey.key");
        FileInputStream fis = new FileInputStream("Assignment2/" + keyPairName +  "ServerPublicKey.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        //read private key
        File filePrivateKey = new File("Assignment2/" + keyPairName +  "ServerPrivateKey.key");
        fis = new FileInputStream("Assignment2/" + keyPairName +  "ServerPrivateKey.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        //create public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        //create private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] encryption(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        data = cipher.doFinal(data);
        System.out.println("Client sending ciphertext: " + Util.bytesToHex(data));
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


    public void decrypt(byte[] message, PrivateKey privateKey) throws Exception {
        System.out.println("\nServer returned ciphertext: " + Util.bytesToHex(message));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        message = cipher.doFinal(message);
        System.out.println("Server returned cleartext: " + new String(message, "UTF-8"));
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
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public void sendMessage(String msg) throws Exception{
        //generate two key-pairs
        KeyPair encryptDecryptKP = keyPairGeneration("Client Encrypt/Decrypt");
        KeyPair signatureKP = keyPairGeneration("Client Signature");

        //save client keys to file
        saveKeyPair(encryptDecryptKP, "EncryptDecrypt");
        saveKeyPair(signatureKP, "Signature");

        //load server keys from file
        KeyPair serverEncryptDecryptKP = loadKeyPair("EncryptDecrypt");
        KeyPair serverSignatureKP = loadKeyPair("Signature");


        Scanner scan = new Scanner(System.in);
        System.out.println("Enter 1 to encrypt-then-sign OR 2 to sign-and-encrypt");
        int result = scan.nextInt();

        if(result == 1){
            //encrypt-then-sign
            System.out.println("Client sending cleartext: " + msg);
            byte[] sendingData = msg.getBytes("UTF-8");
            sendingData = encryption(sendingData, serverEncryptDecryptKP.getPublic());
            byte[] clientSignature = sign(sendingData, signatureKP.getPrivate());
            sendingData = concatenateDataAndSignature(sendingData, clientSignature);
            out.write(sendingData);
            out.flush();

            // decrypt data
            byte[] receivingData = new byte[512];
            byte[] message = new byte[256];
            byte[] serverSignature = new byte[256];
            int numBytes;

            while ((numBytes = in.read(receivingData)) != -1) {
                // decrypt data
                System.arraycopy(receivingData, 0, message, 0, 256);
                System.arraycopy(receivingData, 256, serverSignature, 0, 256);
                decrypt(message, encryptDecryptKP.getPrivate());
                verifySignature(message, serverSignature, serverSignatureKP.getPublic());
            }
        }
        else if(result == 2){
            //sign-and-encrypt
            System.out.println("Client sending cleartext: " + msg);
            byte[] sendingData = msg.getBytes("UTF-8");
            sign(sendingData, signatureKP.getPrivate());
            sendingData = encryption(sendingData, serverEncryptDecryptKP.getPublic());
            out.write(sendingData);
            out.flush();
        }
        else{System.out.println("Invalid input.");}


    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }



    public static void main(String[] args) throws Exception {
        EchoClient client = new EchoClient();
        client.startConnection("127.0.0.1", 4444);
        client.sendMessage("12345678");
        client.sendMessage("ABCDEFGH");
        client.sendMessage("87654321");
        client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
