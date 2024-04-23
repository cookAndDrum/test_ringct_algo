#include <cstring>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sstream>

using namespace std;

void to_string(string *output, unsigned char *key, size_t n) {
  ostringstream oss;
  for (size_t i = 0; i < n; i++) {
    oss << hex << int(key[i]);
  }
}

void fill_seed(int val, unsigned char *seed, size_t n) {
  for (size_t i = 0; i < n; i++)
    seed[i] = val;
}

// to test if the operation is correct (of the libsodium) 
// extract the seed from sk, sk (64 byte) is composed of first 32byte as seed, next 32 byte as pk
void extract_scalar_from_sk (unsigned char* scalar, const unsigned char* seed) {
  crypto_hash_sha512(scalar, seed, 32);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
}

void hash_to_scalar(unsigned char *scalar, unsigned char *key,
                    size_t key_size) {
  unsigned char hash[crypto_generichash_BYTES_MAX];
  crypto_generichash(hash, crypto_generichash_BYTES_MAX, key, key_size, NULL,
                     0);
  crypto_core_ed25519_scalar_reduce(scalar, hash);
}

int main() {
  if (sodium_init() == -1)
    return 1;

  // seed
  unsigned char seed_1[crypto_sign_ed25519_SEEDBYTES];
  unsigned char seed_2[crypto_sign_ed25519_SEEDBYTES];

  fill_seed(1, seed_1, crypto_sign_ed25519_SEEDBYTES);
  fill_seed(2, seed_2, crypto_sign_ed25519_SEEDBYTES);

  // recipient info
  // the secretkeybyte is 64 bytes long, the first 32 byte is replaced with seed and the next 32 byte is replaced with public key
  unsigned char skV_b[crypto_sign_SECRETKEYBYTES];
  unsigned char pkV_b[crypto_sign_PUBLICKEYBYTES];
  unsigned char skS_b[crypto_sign_SECRETKEYBYTES];
  unsigned char pkS_b[crypto_sign_PUBLICKEYBYTES];

  crypto_sign_seed_keypair(pkS_b, skS_b, seed_1);
  crypto_sign_seed_keypair(pkV_b, skV_b, seed_2); // the proper way is use hash_to_scalar
                                     // calculate the skV_b from skS_b

  // 1. sender pick random r
  unsigned char r[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_random(r);
  // 2. sender calculate Hn = (r * pkV_b) G + pkS_b
  // 2.1 compute scalar r * pkV_b
  unsigned char r_pkV_b[crypto_scalarmult_ed25519_BYTES];
  int is_success = crypto_scalarmult_ed25519_noclamp(r_pkV_b, r, pkV_b);
  if (is_success != 0)
    cout << "Scalar operation on r * pkV_b fail" << endl;

  // 2.1 Hn (r_pkV_b)

  // test
  // test if r * skV_b * G == r * pkV_b
  unsigned char test_pkV_b[crypto_sign_PUBLICKEYBYTES];

  cout << "lenght of secret key byte: " << crypto_sign_SECRETKEYBYTES <<endl;

  unsigned char copied_pkV_b_from_sk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char scalar_skV_b[32];
  unsigned char copied_seed_skV_b[crypto_sign_ed25519_SEEDBYTES];
  memcpy(copied_pkV_b_from_sk, skV_b + crypto_sign_ed25519_SEEDBYTES, 32); // clone the pk from sk
  memcpy(copied_seed_skV_b, skV_b, crypto_sign_ed25519_SEEDBYTES); // clone the pk from sk
  extract_scalar_from_sk(scalar_skV_b, copied_seed_skV_b); // extract the sk

  crypto_scalarmult_ed25519_base(test_pkV_b, scalar_skV_b);
  string pkV_b_hex;
  string test_pkV_b_hex;
  // to_string(pkV_b_hex, pkV_b, crypto_sign_PUBLICKEYBYTES);
  // to_string(test_pkV_b_hex, test_pkV_b, crypto_sign_PUBLICKEYBYTES);
  cout << "pkV_b : " << endl;
  for (unsigned char c : pkV_b)
    cout << hex << int(c);
  cout << endl;

  cout << "copied_pkV_b from sk: " << endl;
  for (unsigned char c : copied_pkV_b_from_sk)
    cout << hex << int(c);
  cout << endl;

  cout << "test_pkV_b (calculate from extract the seed from the sk) : " << endl;
  for (unsigned char c : test_pkV_b)
    cout << hex << int(c);
  cout << dec << endl;

  return 0;
}
