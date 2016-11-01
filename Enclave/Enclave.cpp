#include <stdio.h>

#include "Enclave.h"

#include "Enclave_t.h"

int say_hello() {
  char str[] = "Hello SGX!";
  int retval;
  ocall_prints(&retval, str);
}
