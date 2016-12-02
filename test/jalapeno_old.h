#ifndef JALAPENO_H
#define JALAPENO_H

#include "sgx_eid.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

extern sgx_enclave_id_t global_eid;

// Test Code
void print_ec256_pub_key(sgx_ec256_public_t *pub);
void generate_3_keys_and_delete_2();
void generate_2_keys_and_delete_1();
void webserver_ops();

#endif // JALAPENO_H
