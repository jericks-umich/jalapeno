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

#define MAX_PATH FILENAME_MAX

//#define SGX_DEBUG_FLAG 1 // debug mode enabled

// Global enclave id
sgx_enclave_id_t global_eid = 0;

int ocall_prints(const char* str) {
  printf("The enclave prints: \"%s\"\n", str);
}

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

  //int retval;
  //sgx_status_t status;
  //status = say_hello(global_eid, &retval); // enclave ecall
  //printf("Return status from say_hello: %d\n", retval);

  sgx_status_t retval;
  sgx_status_t status;
  sgx_ec256_public_t pub;

  status = genKey(global_eid, &retval, &pub);
  printf("Return status from genKey: %d\n", retval);

  // Print Pub Key for Debug
  for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
  {
    printf("%02X",pub.gx[i]);
    i++;
  }
  printf("\n");
  for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
  {
    printf("%02X",pub.gy[i]);
    i++;
  }
  printf("\n");

  status = delKey(global_eid, &retval, &pub);
  printf("Return status from delKey: %d\n", retval);

#define SECRET_MESSAGE "thisisasecretmessage"
  const uint8_t ciphertext[] = SECRET_MESSAGE;
  uint8_t plaintext[sizeof(SECRET_MESSAGE)];
  uint32_t len = sizeof(SECRET_MESSAGE);
  printf("Calling decrypt on secret message: %s\n", ciphertext);
  status = debug_decrypt(global_eid, &retval, ciphertext, len, &pub, plaintext);
  printf("This is the returned plaintext: %s\n", plaintext);
  printf("Return status from debug_decrypt: %d\n", retval);

#define KNOWN_MESSAGE "thisisaknownmessage"
  const uint8_t new_plaintext[] = KNOWN_MESSAGE;
  uint32_t new_len = sizeof(KNOWN_MESSAGE);
  sgx_ec256_signature_t signature;
  status = debug_sign(global_eid, &retval, plaintext, new_len, &pub, &signature);
  printf("Return status from debug_sign: %d\n", retval);
  printf("This is the returned signature: %u\n", signature.x[0]);

  return 0;
}
