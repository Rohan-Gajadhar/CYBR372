package Part2;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
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
     * Encrypts data using the client's public key
     *
     * @param data byte array of data to be encrypted
     * @param publicKey client's public key
     * @return data, encrypted message in byte array format
     *
     */
    public static byte[] encryption(byte[] data, PublicKey publicKey) throws Exception {
        System.out.println("Server sending cleartext: " + new String(data, "UTF-8"));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        data = cipher.doFinal(data);
        System.out.println("Server sending ciphertext: " + Util.bytesToHex(data));
        return data;
    }

    /**
     * Signs data using the server's private key
     *
     * @param data encrypted byte array of data to be signed
     * @param privateKey server's private key
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
        byte[] message = new byte[data.length + signature.length];
        System.arraycopy(data, 0, message, 0, data.length);
        System.arraycopy(signature, 0, message, data.length, signature.length);
        return message;
    }

    /**
     * Decrypts data using the server's private key
     * Prints received ciphertext, and decrypted plaintext
     *
     * @param message encrypted byte array of data to be decrypted
     * @param privateKey server's private key
     *
     */
    public byte[] decrypt(byte[] message, PrivateKey privateKey) throws Exception {
        System.out.println("\nServer received ciphertext: " + Util.bytesToHex(message));
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        message = cipher.doFinal(message);
        System.out.println("Server received cleartext: " + new String(message, "UTF-8"));
        return message;
    }

    /**
     * Verifies signature using the client's public key
     * Prints whether signature was verified or not
     *
     * @param message byte array of data to be verified and updated
     * @param signature byte array of client signature
     * @param publicKey server's public key
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
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws Exception{
        getKeyPairs();

        serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());


        byte[] receivingData = new byte[512];
        byte[] message = new byte[256];
        byte[] clientSignature = new byte[256];
        int numBytes;

        while ((numBytes = in.read(receivingData)) != -1) {
            //read encryption mode from EncryptionMode.txt to determine how to decrypt and encrypt
            FileInputStream fis = new FileInputStream("Part2/" + "EncryptionMode.txt");
            byte[] encryptionModeByte = new byte[1];
            fis.read(encryptionModeByte);
            fis.close();
            encryptionMode = encryptionModeByte[0];

            //seperate data and signature
            System.arraycopy(receivingData, 0, message, 0, 256); //copy encrypted data into message[]
            System.arraycopy(receivingData, 256, clientSignature, 0, 256); //copy signature into clientSignature[]

            if (encryptionMode == 1) {
                //decrypt
                byte[] sendingData = decrypt(message, serverCipherKeyPair.getPrivate()); //decrypt
                verifySignature(message, clientSignature, clientSignatureKeyPair.getPublic()); //verify signature

                //encrypt
                sendingData = encryption(sendingData, clientCipherKeyPair.getPublic()); //encrypt
                byte[] serverSignature = sign(sendingData, (PrivateKey) serverSignatureKeyPair.getPrivate()); //sign
                sendingData = concatenateDataAndSignature(sendingData, serverSignature); //concatenate data and signature into one array

                //send data
                out.write(sendingData);
                out.flush();
            }
            else if (encryptionMode == 2) {
                //decrypt
                byte[] sendingData = decrypt(message, (PrivateKey) serverCipherKeyPair.getPrivate()); //decrypt
                verifySignature(sendingData, clientSignature, clientSignatureKeyPair.getPublic()); //verify signature

                //encrypt
                byte[] serverSignature = sign(sendingData, (PrivateKey) serverSignatureKeyPair.getPrivate()); //sign
                sendingData = encryption(sendingData, clientCipherKeyPair.getPublic()); //encrypt
                sendingData = concatenateDataAndSignature(sendingData, serverSignature); //concatenate data and signature into one array

                //send data
                out.write(sendingData);
                out.flush();
            }
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
        try {
            if(args.length > 0){
                keyStorePassword = args[0];
            }
            EchoServer server = new EchoServer();
            server.start(4444);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

}
