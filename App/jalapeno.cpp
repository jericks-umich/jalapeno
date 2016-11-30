#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_error.h"

#include "jalapeno.h"
#include "../include/status.h"

#include "Enclave_u.h"

#define MAX_PATH FILENAME_MAX

// TODO: remove this when it is no longer needed
#define STORE_FILENAME "/tmp/sgx_ec256_key_store.dump"

//#define SGX_DEBUG_FLAG 1 // debug mode enabled

// Global enclave id
sgx_enclave_id_t global_eid = 0;

// CDECL tells the compiler that the caller will do arg cleanup
int SGX_CDECL main(int argc, char* argv[]) {
	int ret;
	int updated; // flag for whether the launch token is updated or not (it should be, since we don't pass it a valid one)
	sgx_launch_token_t token = {0};

	// create new enclave
	// https://software.intel.com/sites/products/sgx-sdk-users-guide-windows/Content/sgx_create_enclave.htm
	ret = sgx_create_enclave(ENCLAVE_FILENAME,
	                    	SGX_DEBUG_FLAG,
	                    	&token,
	                    	&updated,
	                    	&global_eid,
	                    	NULL);

	printf("Return status from create: %d\n", ret);

	// Test #3
	webserver_ops();

	// Test #1
	generate_3_keys_and_delete_2();

	// Test #2
	generate_2_keys_flush_and_delete_2();

	// #define SECRET_MESSAGE "thisisasecretmessage"
	// const uint8_t ciphertext[] = SECRET_MESSAGE;
	// uint8_t plaintext[sizeof(SECRET_MESSAGE)];
	// uint32_t len = sizeof(SECRET_MESSAGE);
	// printf("Calling decrypt on secret message: %s\n", ciphertext);
	// status = debug_decrypt(global_eid, &retval, ciphertext, len, &pub, plaintext);
	// printf("This is the returned plaintext: %s\n", plaintext);
	// printf("Return status from debug_decrypt: %d\n", retval);

	// #define KNOWN_MESSAGE "thisisaknownmessage"
	// const uint8_t new_plaintext[] = KNOWN_MESSAGE;
	// uint32_t new_len = sizeof(KNOWN_MESSAGE);
	// sgx_ec256_signature_t signature;
	// status = debug_sign(global_eid, &retval, plaintext, new_len, &pub, &signature);
	// printf("Return status from debug_sign: %d\n", retval);
	// printf("This is the returned signature: %u\n", signature.x[0]);

	return 0;
}

////////////
// OCALLS //
////////////

int ocall_prints( const char* str ) {
  printf("The enclave prints: \"%s\"\n", str);
}

jalapeno_status_t ocall_store_sealed_keys( const uint8_t* sealed_data, uint32_t len ) {
	FILE* fp;
	fp = fopen( STORE_FILENAME, "wb" );
	if (fp == NULL) {
		return J_CANT_OPEN_FILE;
	}
	fwrite( sealed_data, sizeof(uint8_t), len, fp );
	fclose( fp );
	return J_OK;
}

jalapeno_status_t ocall_load_sealed_keys( uint8_t* sealed_data, uint32_t len ) {
	FILE* fp;
	fp = fopen( STORE_FILENAME, "rb" );
	if (fp == NULL) {
		return J_CANT_OPEN_FILE;
	}
	fread( sealed_data, sizeof(uint8_t), len, fp );
	fclose( fp );
	return J_OK;
}

/////////////
// TESTING //
/////////////

void print_ec256_pub_key( sgx_ec256_public_t *pub ){
	printf("Public gx: ");
	for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		printf("%02X",pub->gx[i]);
	}
	printf("\n");
	printf("Public gy: ");
	for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		printf("%02X",pub->gy[i]);
	}
	printf("\n");
}

void generate_3_keys_and_delete_2(){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval_1 = SGX_SUCCESS;
	sgx_status_t 		retval_2 = SGX_SUCCESS;
	sgx_ec256_public_t 	pub_1;
	sgx_ec256_public_t 	pub_2;
	sgx_ec256_public_t 	pub_3;
	int 				num_keys = 0;

	// 1. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 1...\n" );
	status = generate_ec256_key_pair( global_eid, &retval_1, &pub_1 );
	print_ec256_pub_key( &pub_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", retval_1 );

	// 2. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 2...\n" );
	status = generate_ec256_key_pair( global_eid, &retval_1, &pub_2 );
	print_ec256_pub_key( &pub_2 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", retval_1 );

	// 3. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 3...\n" );
	status = generate_ec256_key_pair( global_eid, &retval_1, &pub_3 );
	print_ec256_pub_key( &pub_3 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", retval_1 );

	// 4. Delete key pair 2
	printf( "Deleting  EC256 key pair 2...\n" );
	status = delete_ec256_key_pair( global_eid, &retval_1, &pub_2 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 5. Delete key pair 3
	printf( "Deleting  EC256 key pair 3...\n" );
	status = delete_ec256_key_pair( global_eid, &retval_1, &pub_3 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 6. Flush key store cache
	printf( "Flushing  EC256 key pair store...\n" );
	status = flush_ec256_key_pair_cache( global_eid, &retval_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 7. Remove key store file on disk
	remove( STORE_FILENAME );
	printf( "Deleted sealed key store file.\n\n" );
}

void generate_2_keys_flush_and_delete_2(){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval_1 = SGX_SUCCESS;
	sgx_status_t 		retval_2 = SGX_SUCCESS;
	sgx_ec256_public_t 	pub_1;
	sgx_ec256_public_t 	pub_2;
	int 				num_keys = 0;

	// 1. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 1...\n" );
	status = generate_ec256_key_pair( global_eid, &retval_1, &pub_1 );
	print_ec256_pub_key( &pub_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", retval_1 );

	// 2. Generate EC256 Public-Private Key Pair 2
	printf( "Generating EC256 key pair 2...\n" );
	status = generate_ec256_key_pair( global_eid, &retval_1, &pub_2 );
	print_ec256_pub_key( &pub_2 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", retval_1 );

	// 3. Flush key store cache
	printf( "Flushing  EC256 key pair store...\n" );
	status = flush_ec256_key_pair_cache( global_eid, &retval_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 4. Delete key pair 1
	printf( "Deleting  EC256 key pair 1...\n" );
	status = delete_ec256_key_pair( global_eid, &retval_1, &pub_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 5. Delete key pair 2
	printf( "Deleting  EC256 key pair 2...\n" );
	status = delete_ec256_key_pair( global_eid, &retval_1, &pub_2 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 6. Flush key store cache
	printf( "Flushing  EC256 key pair store...\n" );
	status = flush_ec256_key_pair_cache( global_eid, &retval_1 );
	status = debug_number_ec256_key_pairs( global_eid, &retval_2, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", retval_1 );

	// 7. Remove key store file on disk
	remove( STORE_FILENAME );
	printf( "Deleted sealed key store file.\n\n" );
}



// here's the set of things that would happen with a web server:
// 1) Admin will install and configure web server
//	- Will need to generate pub/priv keypair, use pubkey for certificate
// 2) Will need to accept connections from clients
//	- Clients will make TLS request, certificate will be exchanged with pubkey in it
//	- ECDH protocol will occur -- client will generate EC pub/priv keypair and send pubkey
//		- shared key will be derived on both sides using own privkey + remote pubkey
//		- future data will be encrypted with either shared key directly, or key derived from shared key
//			- in TLS, apparently additional session info is concatenated to shared key, then hash is taken and used as session key
// 3) mid-connection, another connection may initiate
//	- must support multiple sessions, use remote pubkey as index (for now, just recompute shared key as needed)
// 4) The connection ends
//	- We must throw away the ephemeral session key (ECDHE) so that PFS takes effect (ECDH is when we reuse the session key between sessions)

void webserver_ops() {
	sgx_status_t status;
	sgx_status_t retval;
	sgx_ec256_public_t s_pub;
	sgx_ec256_public_t c_pub;
	uint8_t client_random[28] = {0}; // super random ;)
	uint8_t server_random[28] = {0};
	uint32_t c_len = sizeof(client_random);
	uint32_t s_len = sizeof(server_random);
	sgx_aes_gcm_128bit_tag_t mac;
	uint8_t plaintext[32];
	uint32_t plaintext_len = sizeof(plaintext);
	uint8_t ciphertext[32];
	uint32_t ciphertext_len = sizeof(ciphertext);

#define SERVER_MESSAGE "ServerSecretMessage"
#define SERVER_MESSAGE_LEN sizeof(SERVER_MESSAGE)
	memcpy(plaintext, SERVER_MESSAGE, SERVER_MESSAGE_LEN);

	printf("Performing webserver operations.\n");

	// 1) Admin will install and configure web server
	//	- Will need to generate pub/priv keypair, use pubkey for certificate
	printf("Generating server EC256 key pair...\n");
	status = generate_ec256_key_pair(global_eid, &retval, &s_pub);
	printf("EC256 key pair generated. Use to set up CSR.\n");
	print_ec256_pub_key(&s_pub);
	// TODO: we'll need to actually output this in a form that can be used for a CSR
	// TODO: we'll also need to get SGX to sign this so the dev can authenticate it's the right keypair
	
	// 2) Will need to accept connections from clients
	//	- Clients will make TLS request, certificate will be exchanged with pubkey in it
	//	- ECDH protocol will occur -- client will generate EC pub/priv keypair and send pubkey
	//		- shared key will be derived on both sides using own privkey + remote pubkey
	//		- future data will be encrypted with either shared key directly, or key derived from shared key
	//			- in TLS, apparently additional session info is concatenated to shared key, then hash is taken and used as session key

	// We're going to simulate both the client and server here, so first generate a new keypair for the client
	printf("Generating client EC256 key pair...\n");
	status = generate_ec256_key_pair(global_eid, &retval, &c_pub);

	// simulate the server/client exchanging pubkeys
	// ta-da that's done (since we have both in local [untrusted] memory)
	// we're going to leave the client's pubkey in untrusted memory and make the untrusted app hold on to it as part of the session information, since it can't hold onto the session keys anymore

	// since we're not storing the session keys in the enclave (we're going to recompute it each time), we don't have to initialize anything

	// ask the server to encrypt a message for the client
	printf("Asking the server to encrypt the message, %s.\n", plaintext);
	// note: we need the following to compute the pre-master secret, master secret, and session keys:
	// server pub key (to look up server priv key)
	// client pub key
	// ==> this can generate the pre-master secret
	// https://tools.ietf.org/html/rfc2246#page-21
	// clienthello.random
	// serverhello.random
	// ==> this can generate the master secret
	// https://tools.ietf.org/html/rfc5246
	// ==> this can generate the session keys
	status = encrypt_aes_gcm(global_eid, &retval, &mac, ciphertext, ciphertext_len, plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len);

}

