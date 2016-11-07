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
  char str[]          = "Called genKey()";
  int retval          = 0;
  sgx_status_t status = SGX_SUCCESS;

  sgx_ecc_state_handle_t *p_ecc_handle  = NULL;
  sgx_ec256_private_t    *p_private_key = NULL;
  // sgx_ec256_public_t     *p_public_key  = NULL; 

  // Open ECC256 Context
  if(SGXAPI sgx_ecc256_open_context(p_ecc_handle) != SGX_SUCCESS){
    return SGX_ERROR_UNEXPECTED;
  }

  // Generate ECC256 Key Pair with ECC256 Context
  // if(SGXAPI sgx_ecc256_create_key_pair(p_private_key, pub, p_ecc_handle) != SGX_SUCCESS){
  //   return SGX_ERROR_UNEXPECTED;
  // }

  // Close ECC256 Context
  // if(SGXAPI sgx_ecc256_close_context(*p_ecc_handle) != SGX_SUCCESS){
  //   return SGX_ERROR_UNEXPECTED; 
  // }

  // Copy memory of public key
  // memcpy(p_public_key, pub, sizeof(sgx_ec256_public_t));
  ocall_prints(&retval, str);
  // ocall_print_key(&retval, str);
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


