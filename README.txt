CSE508: Network Security, Spring 2016

Homework 3: Plugboard Proxy
-------------------------------------------------------------------------------
Submitted By-

Name - Vinayak Mittal
SBU ID - 110385943
Email- vinayak.mittal@stonybrook.edu

-------------------------------------------------------------------------------

This file contains the high level design of pbproxy - "plugboard" proxy for adding an extra layer of protection to publicly accessible network services. It also describes the files, their usage and how to use the program.

This program follows the following specification:

pbproxy [-l port] -k keyfile [-h] destination port
-l : Reverse-proxy mode: listen for inbound connections on <port> and relay them to <destionation>:<port>
-k : Use the symmetric key contained in <keyfile> (as a hexadecimal string)
-h : Displays this help message
destination : Destination Host Name.
port : Destination port number.

This proxy enables extra layer of encryption to connections towards TCP services. This project contains following files:

1. pbproxy.c
	This file contains the main source code for pbproxy. I have first taken the command line arguments from the user and then parsed using getopt. After successfully validating the data, it first checks whether it is triggered as server mode or client mode by checking the -l option. In server mode, the program creates a socket and starts listening on the public port and spawns a thread for bi-directional communication. However in client mode, the program creates a socket and directly connects the server port. Once a successfull link is established, the client can send data to server. Every data sent from server is first encrypted using AES encryption and passed through pbproxy. Server instance of pbproxy receives the encrypted text and decrypts using the key shared between client and server. And, finally sends the decrypted text to end port of server. 
	
2. resource.h
	This file contains all the header information, struct definitions and other macros used in pbproxy.	
	
3. Makefile
	This file has information to compile the source code and clean the binary file. 

	all: clean mydump

	mydump: pbproxy.c
			gcc -g pbproxy.c -o pbproxy -lpthread -lcrypto

	clean:
			rm -f *.o pbproxy
			
	If libssl is not installed on the system, then please type the following command for successfull compilation:
		sudo apt-get install libssl-dev

4. mykey
	This file contains the secured key shared between sender and receiver. The key is a 16 byte hexadecimal string.
	
5. fake_key
	This file contains a different key used for test case to see when wrong key is provided by client. In this case, some gibberish text will be sent to server and hence a malicious user won't be able to execute any malicious code.
	
6. README
	This file contains how to compile and run the program.

Program Execution:
In order to test my program, I have used two methodolgies:

Method-1:
	I ran the following command on server instance:
	pbproxy -k mykey -l 2222 localhost 22
	This command opens port 2222 and starts listening to any packets received on it and forwards it to port 22 on localhost.

	And, I ran the following command to connect to server:
	ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" vmittal@localhost	

Method-2:
On first instance, I have run the following command:
	nc -l -p 4444
	This command opens the 4444 port on receiver's end.
	
On second instance, I have run the pbproxy in server mode:
	./pbproxy -l 3333 -k mykey localhost 4444
	This command opens the socket at port 3333 and starts listening and once a client sends any data, it decrypts the content and redirects to port 4444. It also supports bi-directional communication, hence it encrypts the data received from port 4444 and sends back to client using port 3333.
	
On third instance, I have run the following command:
	./pbproxy -k mykey localhost 3333
	This command runs the pbproxy in client mode and connects to localhost at port 3333. It sends the encrypted data using key stored in mykey file and pbproxy running at server redirects it to end port.
	
Hence any data sent to or from using pbproxy is always encrypted and provides enhanced security, thus adapting to the given flow in HW description.

ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd
\______________________________/                \___________________________/
             client                                        server           

To handle socket buffer overflow, I have added sleep commant for 0.5 seconds.             
			 		
