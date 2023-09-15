import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.security.*;
import java.io.*;
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
    static Scanner scan = new Scanner(System.in);

    public static KeyPair keyPairGeneration() throws NoSuchAlgorithmException{
        //user enters desired key length

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
            KeyPair serverKP = keyPairGeneration();
            KeyPair signatureKP = keyPairGeneration();

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[256];
            Cipher cipher = Cipher.getInstance(CIPHER);
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {
                // decrypt data
                cipher.init(Cipher.DECRYPT_MODE, serverKP.getPrivate());
                byte[] decrypted = cipher.doFinal(data);
                String msg = new String(decrypted, "UTF-8");
                System.out.println("Server received cleartext "+msg);
                // encrypt response (this is just the decrypted data re-encrypted)
                System.out.println("Server sending ciphertext "+Util.bytesToHex(data));
                out.write(data);
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



