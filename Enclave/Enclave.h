#ifndef ENCLAVE_H
#define ENCLAVE_H

// private function definitions go here (but not public ones, since those are already exposed via edger8r
#include "sgx_tcrypto.h"
#include <unordered_map>

extern std::unordered_map<sgx_ec256_public_t*, sgx_ec256_private_t*> ec256_keys;

sgx_status_t decrypt(const uint8_t* ciphertext, uint32_t len, sgx_ec256_public_t* pub, uint8_t* plaintext);
sgx_status_t sign(const uint8_t* plaintext, uint32_t len, sgx_ec256_public_t* pub, sgx_ec256_signature_t* signature);

#endif // ENCLAVE_H
