TO ENCRYPT: 
Ensure there is a .txt file in src/Part2 to be encrypted
You will need to enter a Base64 secret key as a command line argument to encrypt the file.

Here is an example secret key that was used while testing: 
LDtaZzoKrjAldoqUn473DA==

Example: to encrypt the file "plaintext.txt" to an encrypted file "ciphertext.enc" run the command:
java Part2/FileEncryptor.java enc ((base64 secret key)) plaintext.txt ciphertext.enc

This will generate the file "ciphertext.enc" in the src/Part2 directory.

TO DECRYPT:
Ensure there is a .enc file in src/Part2 to be decrypted

Example: to decrypt the file "ciphertext.enc" to a decrypted file "decrypted.txt" run the command:
java Part2/FileEncryptor.java dec ((base64 secret key)) ciphertext.enc decrypted.txt 

Where base64 secret key is the same key used to encrypt the file.

This will generate the file "decrypted.txt" in the src/Part2 directory.