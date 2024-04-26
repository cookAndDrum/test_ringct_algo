#include <cstring> // For memset
#include <iostream>
#include <openssl/bn.h>
#include <sodium.h>

using namespace std;

int main() {
  // Example unsigned char array (typically from libsodium)
  unsigned char sodium_scalar[32];

  crypto_core_ed25519_scalar_random(sodium_scalar);

  // Convert unsigned char array to BIGNUM
  BIGNUM *bn = BN_new();
  BN_bin2bn(sodium_scalar, 32, bn);

  // Optionally perform operations on bn here

  // Convert BIGNUM back to unsigned char array
  unsigned char output_scalar[32];
  memset(output_scalar, 0,
         sizeof(output_scalar)); // Ensure memory is initialized
  int bytes_written = BN_bn2bin(bn, output_scalar);

  // Output the result to check
  std::cout << "Original Scalar: " << endl;
  for (int i = 0; i < 32; i++) {
    std::cout << std::hex << (int)sodium_scalar[i] << " ";
  }
  std::cout << "\nConverted Back: " << endl;
  for (int i = 0; i < bytes_written; i++) {
    std::cout << std::hex << (int)output_scalar[i] << " ";
  }
  std::cout << std::endl;

  // Cleanup
  BN_free(bn);

  return 0;
}
