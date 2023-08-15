TO ENCRYPT: 
Ensure there is a .txt file in src/Part1 to be encrypted

Example: to encrypt the file "plaintext.txt" to an encrypted file "ciphertext.enc" run the command:
java Part1/FileEncryptor.java enc plaintext.txt ciphertext.enc

This will generate the file "ciphertext.enc" in the src/Part1 directory

Take note of the secret key and iv printed to the console. You will need these to decrypt the file.

TO DECRYPT:
Ensure there is a .enc file in src/Part1 to be decrypted

Example: to decrypt the file "ciphertext.enc" to a decrypted file "decrypted.txt" run the command:
java Part1/FileEncryptor.java dec ((base64 secret key)) ((base64 iv)) ciphertext.enc decryptedplaintext.txt 

Where base64 secret key and base64 iv are the secret key and iv printed to the console when the file was encrypted.