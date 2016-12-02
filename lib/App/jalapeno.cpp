#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_error.h"

#include "jalapeno.h"

#include "Enclave_u.h"

//#define SGX_DEBUG_FLAG 1 // debug mode enabled

///////////////////////////
// API Exposed Functions //
///////////////////////////

// Initialize instance of crypto enclave
jalapeno_status_t init_crypto_enclave( sgx_enclave_id_t* enclave_id ) {
	int ret;
	int updated; // flag for whether the launch token is updated or not (it should be, since we don't pass it a valid one)
	sgx_launch_token_t token = {0};

	// create new enclave
	// https://software.intel.com/sites/products/sgx-sdk-users-guide-windows/Content/sgx_create_enclave.htm
	ret = sgx_create_enclave(
		ENCLAVE_FILENAME,
		SGX_DEBUG_FLAG,
		&token,
		&updated,
		enclave_id,
		NULL );
	if ( ret != 0 ){
		printf("ERROR: failed (%d) to initialize SGX crypto enclave.\n", ret);
		return J_ERROR;
	}
	return J_SUCCESS;
}

// ECALL: generates ec256 key pair, seals it, and saves it to disk
jalapeno_status_t generate_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = generate_ec256_key_pair( enclave_id, &retval, pub_key );
	
	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: deletes ec256 key pair and updates persistent sealed key file to reflect this change
jalapeno_status_t delete_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = delete_ec256_key_pair( enclave_id, &retval, pub_key );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: deletes ALL ec256 key pair and deletes persistent sealed key file
jalapeno_status_t delete_all_ec256_key_pairs( sgx_enclave_id_t enclave_id ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = delete_all_ec256_key_pairs( enclave_id, &retval );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: encrypts plaintext with a TLS session key, which is derived from by a generated ECDH key
jalapeno_status_t tls_encrypt_aes_gcm( 
	sgx_enclave_id_t 			enclave_id, 
	sgx_aes_gcm_128bit_tag_t* 	mac, 
	uint8_t* 					ciphertext, 
	uint8_t*					plaintext,
	uint32_t 					plaintext_len, 
	sgx_ec256_public_t* 		server_pubkey, 
	sgx_ec256_public_t* 		client_pubkey, 
	uint8_t* 					server_random_bytes, 
	uint32_t 					num_server_random_bytes, 
	uint8_t* 					client_random_bytes, 
	uint32_t 					num_client_random_bytes, 
	uint8_t 					is_client ){

	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = encrypt_aes_gcm(
		enclave_id, 
		&retval, 
		mac, 
		ciphertext, 
		plaintext, 
		plaintext_len, 
		server_pubkey, 
		client_pubkey, 
		server_random_bytes, 
		num_server_random_bytes, 
		client_random_bytes, 
		num_client_random_bytes, 
		is_client);
}

// ECALL: decrypts plaintext with a TLS session key, which is derived from by a generated ECDH key
jalapeno_status_t tls_decrypt_aes_gcm(
	sgx_enclave_id_t 			enclave_id, 
	sgx_aes_gcm_128bit_tag_t* 	mac, 
	uint8_t* 					ciphertext, 
	uint8_t*					plaintext, 
	uint32_t 					plaintext_len, 
	sgx_ec256_public_t* 		server_pubkey, 
	sgx_ec256_public_t* 		client_pubkey, 
	uint8_t* 					server_random_bytes, 
	uint32_t 					num_server_random_bytes, 
	uint8_t* 					client_random_bytes, 
	uint32_t 					num_client_random_bytes,  
	uint8_t 					is_client ){

	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = decrypt_aes_gcm(
		enclave_id, 
		&retval, 
		mac, 
		ciphertext, 
		plaintext, 
		plaintext_len, 
		server_pubkey, 
		client_pubkey, 
		server_random_bytes, 
		num_server_random_bytes, 
		client_random_bytes, 
		num_client_random_bytes, 
		is_client);
}

// ECALL (for debugging use only): returns number of stored ec256 key pairs
jalapeno_status_t debug_number_ec256_key_pairs( sgx_enclave_id_t enclave_id, int* num_keys ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = debug_number_ec256_key_pairs( enclave_id, &retval, num_keys );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// Prints out Hex representation of an EC256 public key
void print_ec256_pub_key( sgx_ec256_public_t* pub ){
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
	return J_SUCCESS;
}

jalapeno_status_t ocall_load_sealed_keys( uint8_t* sealed_data, uint32_t len ) {
	FILE* fp;
	fp = fopen( STORE_FILENAME, "rb" );
	if (fp == NULL) {
		return J_CANT_OPEN_FILE;
	}
	fread( sealed_data, sizeof(uint8_t), len, fp );
	fclose( fp );
	return J_SUCCESS;
}

jalapeno_status_t ocall_delete_sealed_keys_file() {
	remove( STORE_FILENAME );
	return J_SUCCESS;
}



