#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>


#include "sgx_urts.h"
#include "sgx_eid.h"
#include "hello.h"

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

  int retval;
  sgx_status_t status;
  status = say_hello(global_eid, &retval); // enclave ecall

  printf("Return status from say_hello: %d\n", retval);

  return 0;
}
