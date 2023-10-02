package Part2;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    static KeyPair clientCipherKeyPair = null;
    static KeyPair clientSignatureKeyPair = null;
    static KeyPair serverCipherKeyPair = null;
    static KeyPair serverSignatureKeyPair = null;

    private static int encryptionMode = -1;
    private static String keyStorePassword = null;

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
     * Gets the key pair from the key store
     *
     * @param alias the alias of the key pair
     * @param keyStorePassword the password of the key store
     * @return key pair
     *
     */
    public KeyPair getKeyPairFromKeyStore(String alias, String keyStorePassword) throws Exception{
        InputStream ins = new FileInputStream("Part2/cybr372.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password

        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);

        //get public and private keys
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
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

    /**
     * User selects whether to encrypt-then-sign or sign-and-encrypt
     * Writes output to .txt file for server to read
     *
     */
    public void setEncryptionMode() throws Exception {
        FileOutputStream fos = new FileOutputStream("Part2/" + "EncryptionMode.txt");
        fos.write(encryptionMode);
        fos.close();
    }

    /**
     * User enters keystore password
     * Gets the key pairs from the key store
     *
     */
    public void getKeyPairs() throws Exception {
        //get the key pairs from key store
        clientCipherKeyPair = getKeyPairFromKeyStore("ClientCipher", keyStorePassword);
        clientSignatureKeyPair = getKeyPairFromKeyStore("ClientSignature", keyStorePassword);
        serverCipherKeyPair = getKeyPairFromKeyStore("ServerCipher", keyStorePassword);
        serverSignatureKeyPair = getKeyPairFromKeyStore("ServerSignature", keyStorePassword);
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
            sendingData = encryption(sendingData, serverCipherKeyPair.getPublic()); //encrypt
            byte[] clientSignature = sign(sendingData, clientSignatureKeyPair.getPrivate()); //sign
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
                decrypted = decrypt(message, clientCipherKeyPair.getPrivate()); //decrypt
                reply = new String(decrypted, "UTF-8");
                verifySignature(message, serverSignature, serverSignatureKeyPair.getPublic()); //verify signature
                break;
            }
        }

        //encrypt-and-sign
        else if (encryptionMode == 2) {
            System.out.println("Client sending cleartext: " + msg);
            byte[] plaintext = msg.getBytes("UTF-8");
            byte[] clientSignature = sign(plaintext, clientSignatureKeyPair.getPrivate()); //sign
            byte[] sendingData = encryption(plaintext, serverCipherKeyPair.getPublic());
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
                decrypted = decrypt(message, clientCipherKeyPair.getPrivate()); //decrypt
                reply = new String(decrypted, "UTF-8");
                verifySignature(decrypted, serverSignature, serverSignatureKeyPair.getPublic()); //verify signature
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
        try {
            if (args.length > 0) {
                encryptionMode = Integer.parseInt(args[0]);
                keyStorePassword = args[1];
            }
            EchoClient client = new EchoClient();
            client.startConnection("127.0.0.1", 4444);
            client.setEncryptionMode();
            client.getKeyPairs();
            client.sendMessage("12345678");
            client.sendMessage("ABCDEFGH");
            client.sendMessage("87654321");
            client.sendMessage("HGFEDCBA");
            client.stopConnection();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
