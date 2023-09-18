import java.io.*;
import java.net.*;
import java.security.*;
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

    public static KeyPair keyPairGeneration() throws NoSuchAlgorithmException{
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
        final PrivateKey privateKey = key.getPrivate();

        //print public key
        System.out.println("Public Key: " + publicKey);
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        return key;
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
            Scanner scan = new Scanner(System.in);
            KeyPair encryptDecryptKP = keyPairGeneration();
            KeyPair signatureKP = keyPairGeneration();

            System.out.println("Enter EchoServer public key: ");
            String echoServerPublicKey = scan.nextLine();

            byte[] encodedServerPublicKey = Base64.getDecoder().decode(echoServerPublicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(encodedServerPublicKey));

            //  System.out.println(Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));

            System.out.println("Client sending cleartext " + msg);
            byte[] data = msg.getBytes("UTF-8");

            //encrypt message
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            data = cipher.doFinal(data);
            System.out.println("Client sending ciphertext" + Util.bytesToHex(data));

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
            //in.read(combined);

            // decrypt data
            byte[] decryptedData = new byte[512];
            byte[] ciphertext = new byte[256];
            byte[] verifySignature = new byte[256];
            int numBytes;
            String reply = null;
            while ((numBytes = in.read(decryptedData)) != -1) {
                // decrypt data
                System.arraycopy(decryptedData, 0, ciphertext, 0, 256);
                System.arraycopy(decryptedData, 256, verifySignature, 0, 256);
                cipher.init(Cipher.DECRYPT_MODE, encryptDecryptKP.getPrivate());
                byte[] decrypted = cipher.doFinal(ciphertext);
                reply = new String(decrypted, "UTF-8");
                System.out.println("Server returned cleartext " + reply);

                //read in and create client signature public key
                System.out.println("Enter server signature public key: ");
                String serverSignaturePublicKey = scan.nextLine();
                byte[] encodedServerSignaturePublicKey = Base64.getDecoder().decode(serverSignaturePublicKey);
                PublicKey signaturePublicKey = kf.generatePublic(new X509EncodedKeySpec(encodedServerSignaturePublicKey));

                //verify signature
                Signature verifySig = Signature.getInstance(SIGNATURE_ALGORITHM);
                verifySig.initVerify(signaturePublicKey);
                verifySig.update(ciphertext);
                boolean verified = verifySig.verify(verifySignature);
                if (verified) {
                    System.out.println("Signature was verified!");
                } else {
                    System.out.println("Signature was unable to be verified.");
                }
                break;
            }
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
        client.sendMessage("12345678");
        //client.sendMessage("ABCDEFGH");
        //client.sendMessage("87654321");
        //client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
