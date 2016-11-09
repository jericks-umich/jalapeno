#ifndef ENCLAVE_H
#define ENCLAVE_H

// private function definitions go here (but not public ones, since those are already exposed via edger8r

#define NUMBER_OF_EC256_KEY_PAIRS 64

typedef struct keypair {
  sgx_ec256_public_t pub;
  sgx_ec256_private_t priv;
} keypair;

sgx_status_t decrypt(const uint8_t* ciphertext, uint32_t len, sgx_ec256_public_t* pub, uint8_t* plaintext);
sgx_status_t sign(const uint8_t* plaintext, uint32_t len, sgx_ec256_public_t* pub, sgx_ec256_signature_t* signature);

#endif // ENCLAVE_H
