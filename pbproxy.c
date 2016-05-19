#include "resource.h"

void displayHelp()
{
        fprintf(stdout, "\nUsage : pbproxy [-l port] -k keyfile [-h] destination port\n");
        fprintf(stdout, "-l : Reverse-proxy mode: listen for inbound connections on <port> and relay them to <destionation>:<port>\n");
        fprintf(stdout, "-k : Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n");
        fprintf(stdout, "-h : Displays this help message\n");
        fprintf(stdout, "destination : Destination Host Name.\n");
        fprintf(stdout, "port : Destination port number.\n");
}

void display_cipher_text(char *title, char *data, int len)
{    
    int i;
    char *p = data;

    printf("%s : ", title);
    for(i=0; i<len; ++i) {
        printf("%02X", *p++);
    }

    printf("\n");        
}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{            
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);    
    memset(state->ecount + 16, 0, 16);     
    memcpy(state->ivec, iv, 16);
}

char *encrypt_buffer(char *buf, int rBytes, char *key)
{
    char *outBuf = (char *) malloc(rBytes + AES_BLOCK_SIZE);

    if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        printf("Error in random bytes generation!\n");
        return NULL;    
    }

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("Error setting encryption key!\n");
        return NULL;
    }

    memcpy(outBuf, iv, AES_BLOCK_SIZE);

    init_ctr(&state, iv);

    AES_ctr128_encrypt(buf, outBuf + AES_BLOCK_SIZE, rBytes, &aes_key, state.ivec, state.ecount, &state.num);

    return outBuf;    
}

char *decrypt_buffer(char *buf, int rBytes, char *key)
{
    char *outBuf = (char *) malloc (rBytes - AES_BLOCK_SIZE);
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("Error setting encryption key!\n");
        return NULL;
    }

    memcpy(iv, buf, AES_BLOCK_SIZE);
    init_ctr(&state, iv);

    AES_ctr128_encrypt(buf + AES_BLOCK_SIZE, outBuf, rBytes - AES_BLOCK_SIZE, &aes_key, state.ivec, state.ecount, &state.num);

    return outBuf;
}

char *read_from_file(char *fName)
{
	char *key = NULL;
	FILE *fr;
	long file_size;
	struct stat st;	

	fr = fopen(fName, "rb");

	if(!fr)
		return NULL;

	if(stat(fName, &st) == 0) {
		file_size = st.st_size;
	} else {
		return NULL;
	}	

	key = (char *) malloc(file_size);

	if(!key)
		return NULL;	
	
	if(fread(key, 1, file_size, fr) != file_size) {				
		free(key);
		return NULL;
	}

	fclose(fr);
	
	return key;
}

int resolve_name_to_ip(char *dest,char *destIp)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if((he = gethostbyname(dest)) == NULL) {
        herror("gethostbyname: ");
        return 1;
    }

    addr_list = (struct  in_addr **) he->h_addr_list;
    
    for(i=0; addr_list[i] != NULL; i++) {
        strcpy(destIp, inet_ntoa(*addr_list[i]));
        return 0;
    }

    return 1;
}

void *perform_function(void *arg)
{
    nw_param *nw = NULL;
    int sock, rBytes, isComm = 1, flags;
    char buf[PAGE_SIZE + AES_BLOCK_SIZE], *outBuf = NULL;    

    if(arg == NULL) {
        printf("No arguments received!\n");
        goto exit_thread;
    }

    nw = (nw_param *) arg;    

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket: ");
        goto exit_thread;
    }

    if(connect(sock, (struct sockaddr *)&nw->dest, sizeof(nw->dest)) == -1) {
        perror("Connect: ");
        goto exit_thread;
    }

    flags = fcntl(nw->sd, F_GETFL);
    if(flags == -1) {
        printf("Flag Error!\n");
        goto close_conn;
    }        

    fcntl(nw->sd, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(sock, F_GETFL);
    if(flags == -1) {
        printf("Flag Error!\n");
        goto close_conn;
    }
        
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    memset(buf, '\0', PAGE_SIZE);

    while(isComm) {
        while((rBytes = read(nw->sd, buf, PAGE_SIZE + AES_BLOCK_SIZE)) > 0) {
            
            if(rBytes < AES_BLOCK_SIZE) {
                printf("Packet Length smaller than 16!\n");
                goto close_conn;
            }

            //display_cipher_text("Client", buf + AES_BLOCK_SIZE, rBytes - AES_BLOCK_SIZE);            
            outBuf = decrypt_buffer(buf, rBytes, nw->key);

            if(outBuf == NULL) {                
                printf("OutBuf is NULL!\n");
                goto close_conn;
            }

            write(sock, outBuf, rBytes - AES_BLOCK_SIZE);

            free(outBuf);
            memset(buf, '\0', PAGE_SIZE + AES_BLOCK_SIZE);

            if(rBytes < PAGE_SIZE)
                break;
        }        

        while((rBytes = read(sock, buf, PAGE_SIZE)) >= 0) {            
            //if(rBytes == 0) goto close_conn;            

            if(rBytes > 0) {                
                outBuf = encrypt_buffer(buf, rBytes, nw->key);

                if(outBuf == NULL) {
                    printf("OutBuf is NULL!\n");
                    goto close_conn;
                }      

                sleep(0.5);
                //display_cipher_text("Server", outBuf, rBytes);                
                write(nw->sd, outBuf, rBytes + AES_BLOCK_SIZE);                                    
                free(outBuf);
                memset(buf, '\0', PAGE_SIZE + AES_BLOCK_SIZE);
            } else {
                if(isComm == 1)
                    isComm = 0;
            }        
        }
    }

close_conn:
    printf("Closing Connection!\n");
    close(sock);
    close(nw->sd);
    free(nw);

exit_thread:
    pthread_exit(0);
}

int main(int argc, char **argv)
{
        int i, c, rBytes;
        int isRPMode = 0, isKeyFile = 0, dPort, iPort;         
        char *fName = NULL, *hostName = NULL, *key = NULL, destIp[100];
        char buf[PAGE_SIZE + AES_BLOCK_SIZE], *outBuf = NULL;                                        
        int sock, len;
        struct sockaddr_in server, dest;        
        nw_param *nw;
        pthread_t thread;              
        
        int sent, cli;

        while((c = getopt(argc, argv, "l:k:h")) != -1) {

                switch(c) {
                        case 'l':
                                isRPMode = 1;
                                iPort = atoi(optarg);
                                break;

                        case 'k':
                                isKeyFile = 1;
                                fName = optarg;
                                break;

                        case 'h':
                                displayHelp();
                                goto exit_point;
                                break;

                        case '?':
                                displayHelp();
                                goto exit_point;
                                break;
                }
        }

        if(isKeyFile == 0 || optind + 2 != argc) {
        	printf("Invalid arguments passed! Type -h for help.\n");
        	goto exit_point;
        }

        hostName = argv[optind];
        dPort = atoi(argv[optind+1]);        

        key = read_from_file(fName);

        if(key == NULL) {
        	printf("Error reading from file!\n");
        	goto exit_point;
        }    

        if (resolve_name_to_ip(hostName, destIp) != 0) {
            goto exit_point;
        }        

        switch(isRPMode)
        {
        	case SERVER:        		

        		if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        			perror("Socket: ");
        			goto exit_point;
        		}

        		server.sin_family = AF_INET;
        		server.sin_port = htons(iPort);
        		server.sin_addr.s_addr = INADDR_ANY;
        		bzero(&server.sin_zero, 0);
        		len = sizeof(struct sockaddr_in);

                dest.sin_family = AF_INET;
                dest.sin_port = htons(dPort);                
                inet_aton(destIp, &(dest.sin_addr)); 
                bzero(&dest.sin_zero, 0);

        		if((bind(sock, (struct sockaddr *)&server, len)) == -1) {
        			perror("Bind: ");
        			goto exit_point;
        		}

        		if(listen(sock, 5) == -1) {
        			perror("Listen: ");
        			goto exit_point;
        		}

        		while(1) {
                    nw = (nw_param *) malloc(sizeof(nw_param));
        			if((nw->sd = accept(sock, (struct sockaddr *)&nw->src, &nw->len)) == -1) {
        				perror("Accept: ");
                        free(nw);
        				goto exit_point;
        			}

                    nw->dest = dest;
                    nw->key = key;      
                    if ((pthread_create(&thread, 0, perform_function, (void *) nw)) != 0) {
                        perror("Thread: ");
                        free(nw);
                    }

                    pthread_detach(thread);
        		}

        		break;

        	case CLIENT:        		  

                if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                    perror("Socket: ");
                    goto exit_point;
                }

                dest.sin_family = AF_INET;
                dest.sin_port = htons(dPort);                
                inet_aton(destIp, &(dest.sin_addr)); 
                bzero(&dest.sin_zero, 0);

                if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
                    perror("Connect: ");
                    goto exit_point;
                }
                   
                fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
                fcntl(sock, F_SETFL, O_NONBLOCK);         

                memset(buf, '\0', PAGE_SIZE + AES_BLOCK_SIZE);

                while(1) {
                    while((rBytes = read(STDIN_FILENO, buf, PAGE_SIZE)) > 0) {
                        //if(rBytes == 0) goto exit_point;

                        outBuf = encrypt_buffer(buf, rBytes, key);

                        if(outBuf == NULL) {  
                            printf("OutBuf is NULL\n");
                            close(sock);                                                    
                            goto exit_point;
                        }                            

                        write(sock, outBuf, rBytes + AES_BLOCK_SIZE);

                        free(outBuf);
                        memset(buf, '\0', PAGE_SIZE + AES_BLOCK_SIZE);

                        if(rBytes < PAGE_SIZE)
                            break;
                    }

                    while((rBytes = read(sock, buf, PAGE_SIZE + AES_BLOCK_SIZE)) > 0) {
                        //if(rBytes == 0) goto exit_point;

                        if(rBytes < AES_BLOCK_SIZE) {
                            printf("Packet Length less than 16 bytes!\n");
                            close(sock);
                            goto exit_point;
                        }

                        outBuf = decrypt_buffer(buf, rBytes, key);

                        if(outBuf == NULL) { 
                            printf("OutBuf is NULL\n");    
                            close(sock);                       
                            goto exit_point;
                        }  

                        write(STDOUT_FILENO, outBuf, rBytes - AES_BLOCK_SIZE);

                        free(outBuf);
                        memset(buf, '\0', PAGE_SIZE + AES_BLOCK_SIZE);

                        if(rBytes < PAGE_SIZE)
                            break;
                    }
                }

        		break;
        }

    exit_point:        
    	return 0;
}
