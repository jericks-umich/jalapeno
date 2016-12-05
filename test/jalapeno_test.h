#ifndef JALAPENO_H
#define JALAPENO_H

#define KEY_STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

// Test Functions
void generate_3_keys_and_delete_2( sgx_enclave_id_t enclave_id );
// void generate_2_keys_and_delete_1();
// void webserver_ops();

#endif // JALAPENO_H
