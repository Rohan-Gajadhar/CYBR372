TO ENCRYPT: 
Ensure there is a .txt file in src/Part3 to be encrypted

Example: to encrypt the file "plaintext.txt" to an encrypted file "ciphertext.enc" run the command:
java Part3/FileEncryptor.java enc "my password" plaintext.txt ciphertext.enc

Where "my password" is any string/phrase you want to use as a password for the encryption.
This will generate the file "ciphertext.enc" in the src/Part1 directory
The secret key will be printed to the console.

TO DECRYPT:
Ensure there is a .enc file in src/Part3 to be decrypted

Example: to decrypt the file "ciphertext.enc" to a decrypted file "decrypted.txt" run the command:
java Part3/FileEncryptor.java dec "my password" ciphertext.enc decryptedplaintext.txt 

Where "my password" is the password you used to encrypt the file.
This will generate the file "decrypted.txt" in the src/Part3 directory.