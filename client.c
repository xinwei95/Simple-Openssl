#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <malloc.h>
#include <resolv.h>
#include <errno.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

#define FAIL -1
#define MAX_LENGTH 1024

int EstablishConnection(const char *hostname)
{
        int sd,port = 443;
        struct hostent *host;
        struct sockaddr_in addr;
	if ( (host = gethostbyname(hostname)) == NULL )
        {
	  perror(hostname);
          abort();
        }

        sd = socket(AF_INET, SOCK_STREAM, 0);
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = *(long*)(host->h_addr);
        if(connect(sd,(struct sockaddr*)&addr, sizeof(addr)) != 0 )
        {
          close(sd); 
          perror(hostname);
          abort();
        }
	else
	{
	  printf("Successfully established connection to %s\n", hostname);
	}

        return sd;
}
void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("\tCertificate: %s\n", subj);
	printf("\tIssuer: %s\n\n", issuer);
} 
void printChainCert(STACK_OF(X509) *stack)
{
	X509 *cert;
	unsigned len = sk_X509_num(stack); //this command is essentially the same as strlen()
	printf("\nDepth of cert: %i\n\n",len);
	printf("Begin Certificate Stack\n");
	printf("--------------------\n");
	for (unsigned i = 0; i < len; i ++)
	{
	  printf("Depth = %i\n",i);
	  printf("-------------------\n");
	  cert = sk_X509_value(stack, i);
	  print_certificate(cert); // This function will print out the issuer and certificate of the pointed value
	  printPubKeyMod(cert); //This function will print out the encryption algorithm used for the cert (also retrieving the modulus and public key if it is RSA)
	  printf("-------------------\n");
	  free(cert);
	}
	printf("End Certificate Stack \n");
}

void printPubKeyMod (X509 *cert)
{

	EVP_PKEY *pkey = NULL;
	int pkey_nid = X509_get_signature_nid(cert); // Every encryption comes with an id 
	const char *sslbuf = OBJ_nid2ln(pkey_nid);   // After getting the id from the cert, this command will find the encryption associated with the id
	printf("Signature Algorithm: %s \n\n",sslbuf);

	if ((pkey = X509_get_pubkey(cert)) == NULL) // retrieving public key
	{
		fprintf(stderr,"Error getting public key from certificate");
	}
	else
	{
		 char *rsa_e_dec, *rsa_n_hex;
 		 RSA *rsa_key;
 		 const BIGNUM *n;
 		 const BIGNUM *e;
    	         if((rsa_key = EVP_PKEY_get1_RSA(pkey)) != NULL) // This returns an RSA *key if successful
		  {
	 		 RSA_get0_key(rsa_key, &n,&e, NULL); // structure of RSA : *e is exponent, *n is modulus
	 		 rsa_e_dec = BN_bn2dec(e); //This command converts binary to decimal
	 		 rsa_n_hex = BN_bn2hex(n);// This command converts binary to hexadecimal
	 		 printf("Public exponent : %s bits\n\n",rsa_e_dec);
	 		 printf("Modulus n : %s\n\n", rsa_n_hex);
			 free(rsa_key);
		   }
	}
	EVP_PKEY_free(pkey);
}

void validateCerts(SSL* ssl)
{



	STACK_OF(X509) *stack = SSL_get_peer_cert_chain(ssl);
	printChainCert(stack);//this calls the function where for loop will be called to iterate through all the certificate in the stack

	if(SSL_get_verify_result(ssl) != X509_V_OK) // This function helps to verify the cert with root CA
	{
	 fprintf(stderr,"Invalid Certificate\n " );
	}
	else
	{
	 printf("\nValidation of certificate successful\n");
	}


}

SSL_CTX* InitCTX(void)
{
        SSL_METHOD  *method;
        SSL_CTX* ctx;
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        method = SSLv23_client_method(); 
        ctx = SSL_CTX_new(method); // to initialize the context structure
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); //Setting verification mode of the ptr
        if (ctx == NULL)
        {
          ERR_print_errors_fp(stderr);
          abort();
        }
	if (! SSL_CTX_load_verify_locations(ctx,NULL,"/etc/ssl/certs")) //loading of Certificates
	{
	  ERR_print_errors_fp(stderr);
	  abort();
	}
	return ctx;
}
char* GetMethod(char *hostname, char *args)
{
	// Message body
	printf("%s\n",hostname);

	char *request = malloc(1024);
	printf("Request: \n");

	sprintf(request,"GET https://%s/%s HTTP/1.1\r\n\r\n", hostname,args);// resourcePath);//host //Host:%s\r\n\r\n
	printf("%s",request);
	return request;
}
char* PostMethod(char *hostname, char *query_path,char *body)
{

	char *rPath;
	rPath = hostname;
	char *rBody;
	rBody = body;
	char *message = malloc(1024);
	

	int contentLength = 0; // consist of length of content-length(14)
	contentLength += strlen(rBody);
	printf("\nPost Message Body\n\n");

	sprintf(message,"POST https://%s/%s HTTP/1.1\r\nContent-Type: application/xml\r\nContent-Length: %d\r\n\r\n%s\r\n",rPath,query_path,contentLength,rBody);
	printf("%s\n",message);

	return message;
}
void communication(char *message,SSL* ssl)
{
				char buffer[BUFSIZ];
				int BUFFER_SIZE  = 8192;
                                int total,write_status,nbytes_write = 0,read_status;
				total = strlen(message);
				int received_byte = 0;



                                        while (nbytes_write < total) //To ensure the whole message content is sent out before moving to response
                                        {
                                                printf("Total size: %i\n",total);
                                                write_status = SSL_write(ssl,message+nbytes_write,total-nbytes_write); // To transmit data into the socket
                                                printf("Writing... %i bytes\n",write_status); 
                                                if (write_status == -1) //if SSL_write return other value than > 0 , it means the write operation fail
                                                {
                                                printf("Error writing\n");
                                                break;
                                                }
                                                nbytes_write += write_status; //  Counter to know how many bytes have been transmitted
                                        }
                                        if (nbytes_write == total)
                                        {
                                        printf("Written %i bytes successfully! \n",nbytes_write);
                                        }

                                        while(1){
                                                read_status = SSL_read(ssl,buffer+received_byte,BUFFER_SIZE-received_byte); // BUFFER size is 1024 
						printf("%i\n",read_status);

						if (read_status <0)
                                                {

                                                        printf("Error receiving message\n");
							break;
                                                }
                                                else if (read_status ==0)
                                                {
                                                        break;

                                                }
						received_byte += read_status;
						printf("Received_byte : %i\n", received_byte);
						if (received_byte ==  BUFFER_SIZE || received_byte > BUFFER_SIZE)
						{
							printf("Unable to contain all of the Server Response!\n");
							break;
						}
                                        }
					printf("\nReceived %i bytes \n", received_byte);
					printf("Response : \n%s\n", buffer);
}
int main()
{
	SSL_CTX *ctx;
	SSL *ssl;
	char *inputs;
	inputs = malloc(256); //initializing with a memory of 256
	int server;
	int options = 0;
	char *message;
	char *arg;
	char *body;
	ctx = InitCTX(); //To create context structure for SSL
	SSL_library_init();
	printf("Please enter website that you want to connect to. \n");
	scanf("%255s",inputs);
	printf("Your input: %s \n" ,inputs);
	server = EstablishConnection(inputs);
	ssl = SSL_new(ctx); //set up new SSL connection state
	SSL_set_fd(ssl, server); // attach socket descriptor
	SSL_set_tlsext_host_name(ssl,inputs);
	 // initiates the TLS/SSL handshake with a server. 
	if (SSL_connect(ssl) == FAIL)
	{
		ERR_print_errors_fp(stderr);
	}
	else // if handshake is successful
	{
		validateCerts(ssl);
	}

	     printf("\n---------------menu----------\n");
	     printf("1)Get Response \n2)POST response\n");
	     scanf("%d",&options);
	     switch(options)
		{


		case 1:	 //GET
				arg = malloc(256); //allocating memory of 256
				printf("Please input the arg that u want to get from the domain (%s): \n", inputs);
				scanf("%255s",arg);
				printf("arg: %s \n",arg);
				message = GetMethod(inputs,arg);
				communication(message,ssl);
				free(arg); //free up after using	
				break;

		case 2:// POST

				body = malloc(256);
			 	arg = malloc(256);
				printf("Please enter arg that u want to post the information to (%s): \n", inputs);
				scanf("%255s",arg);
				printf("Please enter message to be sent:\n");
				scanf("%255s",body);
				
				message = PostMethod(inputs,arg,body);
				communication(message,ssl);
				free(arg);
				free(body);


				break;

		default:
			printf("Please key only 1  or 2\n");
		}


	close(server); //close socket
	SSL_CTX_free(ctx); // release context
	return 0;

}

