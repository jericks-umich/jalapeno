#include <stdio.h>
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_error.h"

#include "Enclave_t.h"
#include "Enclave.h"

////////////
// PUBLIC //
////////////

int say_hello() {
  char str[] = "Hello SGX!";
  int retval;
  ocall_prints(&retval, str);
  return SGX_SUCCESS;
}

// pub is for passing back the new public key
sgx_status_t genKey(sgx_ec256_public_t* pub) {
  char str[] = "Called genKey()";
  int retval;
  ocall_prints(&retval, str);
  return SGX_SUCCESS;
}

// pub is input for finding the keypair to delete them
sgx_status_t delKey(sgx_ec256_public_t* pub) {
  char str[] = "Called delKey()";
  int retval;
  ocall_prints(&retval, str);
  return SGX_SUCCESS;
}

/////////////
// PRIVATE //
/////////////

// ciphertext, len, and pub are inputs, plaintext is output
sgx_status_t decrypt(const uint8_t* ciphertext, uint32_t len, sgx_ec256_public_t* pub, uint8_t* plaintext) {
  char str[] = "Called decrypt()";
  int retval;
  ocall_prints(&retval, str);

// this part is just for testing
  char test_str[] = "timisadork";
  memcpy(plaintext, test_str, sizeof(test_str));
  return SGX_SUCCESS;
}

// plaintext, len, and pub are inputs, signature is output
sgx_status_t sign(const uint8_t* plaintext, uint32_t len, sgx_ec256_public_t* pub, sgx_ec256_signature_t* signature) {
  char str[] = "Called sign()";
  int retval;
  ocall_prints(&retval, str);

// this part is just for testing
  signature->x[0] = 3;
  return SGX_SUCCESS;
}



//////////////////
// PUBLIC DEBUG //
//////////////////

// ciphertext, len, and pub are inputs, plaintext is output
sgx_status_t debug_decrypt(const uint8_t* ciphertext, uint32_t len, sgx_ec256_public_t* pub, uint8_t* plaintext) {
  char str[] = "Called debug_decrypt()";
  int retval;
  ocall_prints(&retval, str);
  return decrypt(ciphertext, len, pub, plaintext); // calls private function
}

// plaintext, len, and pub are inputs, signature is output
sgx_status_t debug_sign(const uint8_t* plaintext, uint32_t len, sgx_ec256_public_t* pub, sgx_ec256_signature_t* signature) {
  char str[] = "Called debug_sign()";
  int retval;
  ocall_prints(&retval, str);
  return sign(plaintext, len, pub, signature); // calls private function
}


