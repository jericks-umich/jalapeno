#ifndef JALAPENO_TEST_H
#define JALAPENO_TEST_H

#include "../include/status.h"
#include "sgx_eid.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

// API Exposed Functions
jalapeno_status_t init_crypto_enclave( sgx_enclave_id_t* enclave_id );
jalapeno_status_t generate_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key );
jalapeno_status_t delete_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key );
jalapeno_status_t delete_all_ec256_key_pairs( sgx_enclave_id_t enclave_id );
jalapeno_status_t encrypt_aes_gcm( 
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
	uint8_t 					is_client );
jalapeno_status_t decrypt_aes_gcm(
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
	uint8_t 					is_client );

// API Exposed Debug Functions
jalapeno_status_t debug_number_ec256_key_pairs( sgx_enclave_id_t enclave_id, int* num_keys );
void print_ec256_pub_key( sgx_ec256_public_t* pub );

#endif // JALAPENO_TEST_H