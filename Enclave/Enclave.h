#ifndef ENCLAVE_H
#define ENCLAVE_H

// private function definitions go here (but not public ones, since those are already exposed via edger8r

#define NUMBER_OF_EC256_KEY_PAIRS 64

typedef struct _ec256_key_pair_t {
	sgx_ec256_public_t pub;
	sgx_ec256_private_t priv;
} ec256_key_pair_t;

typedef struct _ec256_key_handle_t{
	bool 			 in_use;
	ec256_key_pair_t key_pair;
} ec256_key_handle_t;

sgx_status_t load_ec256_keys();
sgx_status_t store_ec256_keys();
int get_num_ec256_key_pairs();
sgx_status_t decrypt(const uint8_t* ciphertext, uint32_t len, sgx_ec256_public_t* pub, uint8_t* plaintext);
sgx_status_t sign(const uint8_t* plaintext, uint32_t len, sgx_ec256_public_t* pub, sgx_ec256_signature_t* signature);
void hmac_sha256(sgx_sha256_hash_t* hash, uint8_t* key, uint32_t key_len, uint8_t* msg, uint32_t msg_len);

#endif // ENCLAVE_H
