#ifndef HELLO_H
#define HELLO_H

#include "sgx_eid.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;

#endif // HELLO_H
