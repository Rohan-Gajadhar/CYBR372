import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

import javax.crypto.Cipher;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static KeyPair kp = null;

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

    public static KeyPair keyPairGeneration() throws NoSuchAlgorithmException{
        //user enters desired key length
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter a key length (eg: 1024, 2048, 4096)");
        int keyLength = scan.nextInt();
        scan.close();

        //generate key pair
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        KeyPair key = keyGen.generateKeyPair();

        //get public and private keys
        final PublicKey publicKey = key.getPublic();
        final PrivateKey privateKey = key.getPrivate();

        //print public key
        //System.out.println("Public Key: " + publicKey);

        return key;
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
            System.out.println("Client sending cleartext "+msg);
            byte[] data = msg.getBytes("UTF-8");
            
            //encrypt message
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            data = cipher.doFinal(data);
            System.out.println("Client sending ciphertext before sig "+Util.bytesToHex(data));

            //sign message
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initSign(kp.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();
            
            System.out.println("Client sending ciphertext after sig"+Util.bytesToHex(data));
            out.write(data);
            out.flush();
            in.read(data);
            // decrypt data
            String reply = new String(data, "UTF-8");
            System.out.println("Server returned cleartext "+reply);
            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
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



    public static void main(String[] args) throws NoSuchAlgorithmException {
        EchoClient client = new EchoClient();
        client.startConnection("127.0.0.1", 4444);
        kp = keyPairGeneration();
        client.sendMessage("12345678");
        //client.sendMessage("ABCDEFGH");
        //client.sendMessage("87654321");
        //client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
