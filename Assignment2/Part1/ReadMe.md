`cd Part1`

`javac *.java` to compile all java files

To run:

Open two terminals, one for the server and one for the client.

`cd ..` OR `cd Assignment2`

Server terminal:

`java Part1/EchoServer.java 2048` where `arg[0]` is the key length

Client terminal:

    Encryption mode command line argument: 

    Use '1' for encrypt-then-sign(EtC) or '2' for encrypt-and-sign(E&C)

`java Part1/EchoClient.java 2048 1` where `arg[0]` is the key length and `arg[1]` is the encryption mode.
