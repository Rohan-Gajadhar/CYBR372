Part 2 should contain java files and class files, pre-compiled.

To compile (if needed):

`cd Part2`

`javac *.java` to compile all java files

To run:

Open two terminals, one for the server and one for the client.

`cd Assignment2` (if not already in the directory)

Server terminal:

`java Part2/EchoServer.java badpassword` 

`arg[0]` is the keystore password

Client terminal:

    Encryption mode command line argument: 

    Use '1' for encrypt-then-sign(EtC) or '2' for encrypt-and-sign(E&C)

`java Part2/EchoClient.java 1 badpassword`

`arg[0]` is the encryption mode

`arg[1]` is the keystore password.
