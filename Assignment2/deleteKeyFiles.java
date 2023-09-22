import java.io.File;
import java.util.ArrayList;

public class deleteKeyFiles {
    public static void main(String[] args){
        ArrayList<String> files = new ArrayList<String>();
        files.add("Assignment2/EncryptDecryptClientPrivateKey.key");
        files.add("Assignment2/EncryptDecryptClientPublicKey.key");
        files.add("Assignment2/EncryptDecryptServerPrivateKey.key");
        files.add("Assignment2/EncryptDecryptServerPublicKey.key");
        files.add("Assignment2/SignatureClientPrivateKey.key");
        files.add("Assignment2/SignatureClientPublicKey.key");
        files.add("Assignment2/SignatureServerPrivateKey.key");
        files.add("Assignment2/SignatureServerPublicKey.key");

        for(int i = 0; i<=7; i++){
            File f = new File(files.get(i));
            f.delete();
        }
    }
}
