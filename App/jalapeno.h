#ifndef JALAPENO_H
#define JALAPENO_H

#include "sgx_eid.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;

// Test Code
void print_ec256_pub_key(sgx_ec256_public_t *pub);

#endif // JALAPENO_H
