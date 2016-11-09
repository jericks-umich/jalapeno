#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "Enclave_t.h"
#include "Enclave.h"

////////////
// PUBLIC //
////////////

keypair ec256_key_pairs[ NUMBER_OF_EC256_KEY_PAIRS ];

int say_hello() {
	char str[] = "Hello SGX!";

	int retval;
	ocall_prints(&retval, str);
	return SGX_SUCCESS;
}

// pub is for passing back the new public key
sgx_status_t genKey(sgx_ec256_public_t* pub) {
	// allocate local variables
	int retval; // debug print return value

	jalapeno_status_t 		j_status = J_OK; // custom status value
	sgx_status_t 			status   = SGX_SUCCESS; // SGX status value
	sgx_ecc_state_handle_t 	ecc_handle;
	keypair 				kp; // defined in Enclave.h, includes public and private key members
	uint32_t 				kp_len = sizeof(kp);
	uint32_t 				seal_size = 0;
	sgx_sealed_data_t* 		sealed_data;

	#define MAC_TEXT "JALAPENO v1.0"
	uint8_t mac_text[sizeof(MAC_TEXT)];
	uint8_t mac_text_check[sizeof(MAC_TEXT)];
	memcpy(mac_text, MAC_TEXT, sizeof(MAC_TEXT));
	uint32_t mac_text_len = sizeof(MAC_TEXT);

	// calculate how much space the sealed keys will take
	//seal_size = sgx_calc_sealed_data_size(mac_text_len, kp_len);
	seal_size = sgx_calc_sealed_data_size(0, kp_len);
	if (seal_size == UINT32_MAX) {
		return SGX_ERROR_OUT_OF_MEMORY;
	}

	// attempt to restore existing key from disk
	sealed_data = (sgx_sealed_data_t*) malloc(seal_size);
	status = ocall_retrieve_sealed_keys(&j_status, (uint8_t*) sealed_data, seal_size);
	if (status != SGX_SUCCESS) {
		free(sealed_data);
		return status;
	}

	if (j_status == J_OK) { // if we retrieved the sealed data from disk successfully
		char msg2[] = "Retrieved keypair from disk";
		ocall_prints(&retval, msg2);
		// attempt to unseal existing keypair into our local keypair var
		//status = sgx_unseal_data(sealed_data, mac_text_check, &mac_text_len, (uint8_t*) &kp, &kp_len);
		status = sgx_unseal_data(sealed_data, NULL, 0, (uint8_t*) &kp, &kp_len);
		free(sealed_data);
		if (status != SGX_SUCCESS) {
			return status;
		}
		// check if mac_text matches
		//if (memcmp(mac_text, mac_text_check, mac_text_len) != 0) {
		//  return SGX_ERROR_UNEXPECTED;
		//}
		char msg3[] = "Successfully unsealed keypair";
		ocall_prints(&retval, msg3);
		memcpy(pub, &kp.pub, sizeof(sgx_ec256_public_t));
		return SGX_SUCCESS;
	}
	free(sealed_data);

	// if we get here, then we were unable to retrieve the keypair and should make a new one
	char msg4[] = "Creating new keypair";
	ocall_prints(&retval, msg4);

	// Open ECC256 Context
	status = sgx_ecc256_open_context(&ecc_handle);
	if (status != SGX_SUCCESS) {
		return status;
	}

	// Generate ECC256 Key Pair with ECC256 Context
	status = sgx_ecc256_create_key_pair(&kp.priv, &kp.pub, ecc_handle);
	if (status != SGX_SUCCESS) {
		return status;
	}

	// Close ECC256 Context
	status = sgx_ecc256_close_context(ecc_handle);
	if (status != SGX_SUCCESS) {
		return status;
	}

	// Seal keys for storage
	sealed_data = (sgx_sealed_data_t*) malloc(seal_size);
	//status = sgx_seal_data(mac_text_len, mac_text, kp_len, (uint8_t*) &kp, seal_size, sealed_data);
	status = sgx_seal_data(0, NULL, kp_len, (uint8_t*) &kp, seal_size, sealed_data);
	if (status != SGX_SUCCESS) {
	char msg41[] = "Problem sealing data";
	ocall_prints(&retval, msg41);
	free(sealed_data);
		return status;
	}
	char msg5[] = "Sealed keys";
	ocall_prints(&retval, msg5);

	// store the public and private key to disk
	status = ocall_store_sealed_keys(&j_status, (uint8_t*) sealed_data, seal_size);
	free(sealed_data);
	if (status != SGX_SUCCESS) {
		return status;
	}
	if (j_status != J_OK) {
	// TODO: log something using j_status
		return SGX_ERROR_UNEXPECTED;
	}

	char msg6[] = "Stored sealed keys";
	ocall_prints(&retval, msg6);

	// Copy memory of public key to return buffer and return
	memcpy(pub, &kp.pub, sizeof(sgx_ec256_public_t));

	char msg7[] = "This is a debug test";
	ocall_prints(&retval, msg7);

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


