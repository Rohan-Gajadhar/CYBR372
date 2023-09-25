package Part1;

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

    KeyPair encryptDecryptKP = null;
    KeyPair signatureKP = null;
    KeyPair serverEncryptDecryptKP = null;
    KeyPair serverSignatureKP = null;

    private static int encryptionMode = -1;

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

    /**
     * Generates a key pair using a public and private key
     * Prints public key as-is to console and in base64 (human-readable format of modulus and exponent)
     *
     * @param keyPairName identifies what the key-pair is used for (encrypt/decrypt, or signature)
     * @return key pair
     *
     */
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

    /**
     * Saves the generated key-pair to a file (.key) in the same directory as the program
     * Encodes the public and private keys, so they are not in plaintext format
     *
     * @param kp key-pair to be saved
     * @param keyPairName identifies which key-pair is being saved (encrypt/decrypt, or signature)
     *
     */
    public static void saveKeyPair(KeyPair kp, String keyPairName){
        //encode public and private keys
        X509EncodedKeySpec encodedPublicKey = new X509EncodedKeySpec(kp.getPublic().getEncoded());
        PKCS8EncodedKeySpec encodedPrivateKey = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        try {
            //write public key
            FileOutputStream fos = new FileOutputStream("Assignment2/Part1/" + keyPairName + "ClientPublicKey.key");
            fos.write(encodedPublicKey.getEncoded());
            fos.close();

            //write private key
            fos = new FileOutputStream("Assignment2/Part1/" + keyPairName + "ClientPrivateKey.key");
            fos.write(encodedPrivateKey.getEncoded());
            fos.close();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    /**
     * Loads the server key-pair from a file (.key) in the same directory as the program
     * Reconstructs public and private keys from encoded keys
     *
     * @param keyPairName identifies which key-pair is being loaded (encrypt/decrypt, or signature)
     * @return key-pair, containing reconstructed public and private keys
     *
     */
    public static KeyPair loadKeyPair(String keyPairName) throws Exception{
        //read public key
        File filePublicKey = new File("Assignment2/Part1/" + keyPairName +  "ServerPublicKey.key");
        FileInputStream fis = new FileInputStream("Assignment2/Part1/" + keyPairName +  "ServerPublicKey.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        //read private key
        File filePrivateKey = new File("Assignment2/Part1/" + keyPairName +  "ServerPrivateKey.key");
        fis = new FileInputStream("Assignment2/Part1/" + keyPairName +  "ServerPrivateKey.key");
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

    /**
     * Creates key-pairs for encrypt/decrypt and signature
     * Saves client keys to file
     * Loads server keys from file
     * Prevents the need for keys to be regenerated each time a message is sent via sendMessage()
     *
     */
    public void keyInstantiation() throws Exception {
        //generate two key-pairs
        encryptDecryptKP = keyPairGeneration("Client Encrypt/Decrypt");
        signatureKP = keyPairGeneration("Client Signature");

        //save client keys to file
        saveKeyPair(encryptDecryptKP, "EncryptDecrypt");
        saveKeyPair(signatureKP, "Signature");

        //load server keys from file
        serverEncryptDecryptKP = loadKeyPair("EncryptDecrypt");
        serverSignatureKP = loadKeyPair("Signature");
    }

    /**
     * Encrypts data using the server's public key
     *
     * @param data byte array of data to be encrypted
     * @param publicKey server's public key
     * @return data, encrypted message in byte array format
     *
     */
    public static byte[] encryption(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        data = cipher.doFinal(data);
        System.out.println("Client sending ciphertext: " + Util.bytesToHex(data));

        return data;
    }

    /**
     * Signs data using the client's private key
     *
     * @param data encrypted byte array of data to be signed
     * @param privateKey client's private key
     * @return signature, in byte array format
     *
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(privateKey);
        sig.update(data);

        return sig.sign();
    }

    /**
     * Concatenates data and signature into one byte array for sending
     *
     * @param data encrypted byte array of data
     * @param signature byte array of signature
     * @return message, byte array of data and signature
     *
     */
    public static byte[] concatenateDataAndSignature(byte[] data, byte[] signature) {
        byte[] message = new byte[data.length + signature.length]; //data and signature are both 256 bytes
        System.arraycopy(data, 0, message, 0, data.length); //copy data into message
        System.arraycopy(signature, 0, message, data.length, signature.length); //copy signature into message

        return message;
    }


    /**
     * Decrypts data using the client's private key
     * Prints received ciphertext, and decrypted plaintext
     *
     * @param message encrypted byte array of data to be decrypted
     * @param privateKey client's private key
     *
     */
    public byte[] decrypt(byte[] message, PrivateKey privateKey) throws Exception {
        System.out.println("\nServer returned ciphertext: " + Util.bytesToHex(message));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        message = cipher.doFinal(message);
        String reply = new String(message, "UTF-8");
        System.out.println("Server returned cleartext: " + reply);
        return message;
    }

    /**
     * Verifies signature using the server's public key
     * Prints whether signature was verified or not
     *
     * @param message byte array of data to be verified and updated
     * @param signature byte array of server signature
     * @param publicKey client public key
     *
     */
    public void verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message);

        boolean verified = sig.verify(signature);
        if (verified) {
            System.out.println("\nSignature was verified!\n");
        } else {
            System.out.println("\nSignature was unable to be verified.\n");
        }
    }

    public void setEncryptionMode() throws Exception {
        //user selects whether to encrypt-then-sign or sign-and-encrypt
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter 1 to encrypt-then-sign OR 2 to sign-and-encrypt");
        encryptionMode = scan.nextInt();
        FileOutputStream fos = new FileOutputStream("Assignment2/Part1/" + "EncryptionMode.txt");
        fos.write(encryptionMode);
        fos.close();
    }


    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) throws Exception {
        String reply = null;

        //encrypt-then-sign
        if (encryptionMode == 1) {
            System.out.println("Client sending cleartext: " + msg);

            byte[] sendingData = msg.getBytes("UTF-8"); //convert message to byte array
            sendingData = encryption(sendingData, serverEncryptDecryptKP.getPublic()); //encrypt
            byte[] clientSignature = sign(sendingData, signatureKP.getPrivate()); //sign
            sendingData = concatenateDataAndSignature(sendingData, clientSignature); //concatenate data and signature into one array

            //send data
            out.write(sendingData);
            out.flush();

            // decryption
            byte[] receivingData = new byte[512];
            byte[] message = new byte[256];
            byte[] serverSignature = new byte[256];
            byte[] decrypted = new byte[256];
            int numBytes;

            while ((numBytes = in.read(receivingData)) != -1) {
                //seperate data and signature
                System.arraycopy(receivingData, 0, message, 0, 256); //copy encrypted data into message[]
                System.arraycopy(receivingData, 256, serverSignature, 0, 256); //copy signature into serverSignature[]
                decrypted = decrypt(message, encryptDecryptKP.getPrivate()); //decrypt
                reply = new String(decrypted, "UTF-8");
                verifySignature(message, serverSignature, serverSignatureKP.getPublic()); //verify signature
                break;
            }
        }

        //sign-and-encrypt
        //encrypt message, sign the message
        else if (encryptionMode == 2) {
            System.out.println("Client sending cleartext: " + msg);
            byte[] plaintext = msg.getBytes("UTF-8");
            byte[] clientSignature = sign(plaintext, signatureKP.getPrivate()); //sign
            byte[] sendingData = encryption(plaintext, serverEncryptDecryptKP.getPublic());
            sendingData = concatenateDataAndSignature(sendingData, clientSignature);
            out.write(sendingData);
            out.flush();

            // decryption
            byte[] receivingData = new byte[512];
            byte[] message = new byte[256];
            byte[] serverSignature = new byte[256];
            byte[] decrypted = new byte[256];
            int numBytes;

            while ((numBytes = in.read(receivingData)) != -1) {
                //seperate data and signature
                System.arraycopy(receivingData, 0, message, 0, 256); //copy encrypted data into message[]
                System.arraycopy(receivingData, 256, serverSignature, 0, 256); //copy signature into serverSignature[]
                decrypted = decrypt(message, encryptDecryptKP.getPrivate()); //decrypt
                reply = new String(decrypted, "UTF-8");
                verifySignature(decrypted, serverSignature, serverSignatureKP.getPublic()); //verify signature
                break;
            }
        } else {
            System.out.println("Invalid input.");
        }
        return reply;
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
        client.keyInstantiation();
        client.setEncryptionMode();
        client.sendMessage("12345678");
        client.sendMessage("ABCDEFGH");
        client.sendMessage("87654321");
        client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
