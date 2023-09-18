import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.security.*;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
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

    public static KeyPair keyPairGeneration() throws NoSuchAlgorithmException{
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
        System.out.println("Public Key: " + publicKey);
        System.out.println("Public Key: \n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        return key;
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            KeyPair encryptDecryptKP = keyPairGeneration();
            KeyPair signatureKP = keyPairGeneration();

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[512];
            byte[] ciphertext = new byte[256];
            byte[] verifySignature = new byte[256];

            Cipher cipher = Cipher.getInstance(CIPHER);
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {
                // decrypt data
                System.arraycopy(data, 0, ciphertext, 0, 256);
                System.arraycopy(data, 256, verifySignature, 0, 256);
                cipher.init(Cipher.DECRYPT_MODE, encryptDecryptKP.getPrivate());
                byte[] decrypted = cipher.doFinal(ciphertext);
                String msg = new String(decrypted, "UTF-8");
                System.out.println("Server received cleartext "+msg);

                //read in and create client signature public key
                Scanner scan = new Scanner(System.in);
                System.out.println("Enter client signature public key: ");
                String clientSignaturePublicKey = scan.nextLine();
                byte[] encodedClientSignaturePublicKey = Base64.getDecoder().decode(clientSignaturePublicKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey signaturePublicKey = kf.generatePublic(new X509EncodedKeySpec(encodedClientSignaturePublicKey));

                //verify signature
                Signature verifySig = Signature.getInstance(SIGNATURE_ALGORITHM);
                verifySig.initVerify(signaturePublicKey);
                verifySig.update(ciphertext);
                boolean verified = verifySig.verify(verifySignature);
                if(verified){System.out.println("Signature was verified!");}
                else{System.out.println("Signature was unable to be verified.");}

                // read in and create client public key for encryption
                System.out.println("Enter EchoClient public key: ");
                String echoClientPublicKey = scan.nextLine();
                byte[] encodedClientPublicKey = Base64.getDecoder().decode(echoClientPublicKey);
                PublicKey clientPublicKey = kf.generatePublic(new X509EncodedKeySpec(encodedClientPublicKey));

                // encrypt response (this is just the decrypted data re-encrypted)
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] encrypted = cipher.doFinal(decrypted);
                System.out.println("Server sending ciphertext "+Util.bytesToHex(encrypted));

                //sign message
                Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
                sig.initSign(signatureKP.getPrivate());
                sig.update(encrypted);
                byte[] signature = sig.sign();
                byte[] combined = new byte[encrypted.length + signature.length];
                System.arraycopy(encrypted, 0, combined, 0, encrypted.length);
                System.arraycopy(signature, 0, combined, encrypted.length, signature.length);
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



