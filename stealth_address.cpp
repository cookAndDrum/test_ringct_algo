#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
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
    oss << hex << setw(2) << setfill('0') << int(key[i]);
  }
}

void print_hex(const unsigned char *key, size_t n) {
  for (size_t i = 0; i < n; i++) {
    cout << hex << setw(2) << setfill('0') << int(key[i]);
  }
  cout << endl;
}

void compare_byte(const unsigned char *a, const unsigned char *b, size_t n) {
  if (memcmp(a, b, n) == 0)
    cout << "Both byte strings equal" << endl;
  else
    cout << "WARNING>> Both byte strings are not equal" << endl;
}

void fill_seed(int val, unsigned char *seed, size_t n) {
  for (size_t i = 0; i < n; i++)
    seed[i] = val;
}

void extract_scalar_from_sk(unsigned char *scalar, const unsigned char *seed) {
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

void sender_compute_stealth_address_and_test(
    unsigned char *one_time_key_address, unsigned char *r,
    const unsigned char *pkV_b, const unsigned char *pkS_b) {
  // 1. sender pick random r
  crypto_core_ed25519_scalar_random(r); // TODO change to random scalar
  // 2. sender calculate Hn = (r * pkV_b) G + pkS_b
  // 2.1 compute scalar r * pkV_b
  unsigned char r_pkV_b[crypto_scalarmult_ed25519_BYTES];
  int is_success = crypto_scalarmult_ed25519_noclamp(r_pkV_b, r, pkV_b);
  if (is_success != 0)
    cout << "Scalar operation on r * pkV_b fail" << endl;

  // 2.1 Hn (r_pkV_b)
  unsigned char hn_r_pkV_b[crypto_core_ed25519_SCALARBYTES];
  hash_to_scalar(hn_r_pkV_b, r_pkV_b, crypto_core_ed25519_SCALARBYTES);
  cout << "Length of the ed25519 scalarbyte: "
       << crypto_core_ed25519_SCALARBYTES << endl;
  // 2.2 scalar multiplication
  unsigned char G_hn_r_pkV_b[crypto_core_ed25519_SCALARBYTES];
  is_success = crypto_scalarmult_ed25519_base_noclamp(G_hn_r_pkV_b, hn_r_pkV_b);
  if (is_success != 0)
    cout << "Scalar operation of G with hash scalar fails" << endl;

  // 3 point addition of Hn*G and pkS_b
  is_success =
      crypto_core_ed25519_add(one_time_key_address, G_hn_r_pkV_b, pkS_b);
  if (is_success != 0)
    cout << "Point addition for one time address fail due to invalid point"
         << endl;
}

void test_scalar_arithmetic() {
  cout << "inside test scalar arithmetic " << endl;
  unsigned char a[crypto_core_ed25519_BYTES];
  unsigned char b[crypto_core_ed25519_BYTES];
  unsigned char A[crypto_core_ed25519_SCALARBYTES];
  unsigned char B[crypto_core_ed25519_SCALARBYTES];
  unsigned char C[crypto_core_ed25519_SCALARBYTES];
  unsigned char test_B[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_random(a);
  crypto_core_ed25519_random(b);
  hash_to_scalar(A, a, crypto_core_ed25519_SCALARBYTES);
  hash_to_scalar(B, b, crypto_core_ed25519_SCALARBYTES);

  // C = B + A mod l
  crypto_core_ed25519_scalar_add(C, B, A);
  // test_B = C - A mod l
  crypto_core_ed25519_scalar_sub(test_B, C, A);

  cout << "B: " << endl;
  print_hex(B, crypto_core_ed25519_SCALARBYTES);
  cout << "test_B: " << endl;
  print_hex(test_B, crypto_core_ed25519_SCALARBYTES);
  compare_byte(B, test_B, crypto_core_ed25519_SCALARBYTES);
  cout << "==========================================" << endl;


  unsigned char D[crypto_core_ed25519_SCALARBYTES];
  unsigned char E[crypto_core_ed25519_SCALARBYTES];
  unsigned char F[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_random(D);
  crypto_core_ed25519_scalar_random(E);

}

void receiver_test_compute(const unsigned char *skV_b,
                           const unsigned char *pkV_b,
                           const unsigned char *skS_b,
                           const unsigned char *pkS_b,
                           const unsigned char *r,
                           const unsigned char *stealth_address) {
  cout << " inside receiver test compute " << endl;

  // get skV_b scalar
  unsigned char scalar_skV_b[32];
  extract_scalar_from_sk(scalar_skV_b, skV_b); // extract the sk
  // rG given by sender
  unsigned char rG[crypto_core_ed25519_BYTES]; // given by the sender
  crypto_scalarmult_ed25519_base_noclamp(rG, r);
  // Compute parameter inside hash to scalar
  unsigned char rG_skV_b[crypto_core_ed25519_BYTES];
  int is_success = crypto_scalarmult_ed25519(rG_skV_b, scalar_skV_b, rG);
  if (is_success != 0)
    cout << "Scalar operation failure in rG_skV_b." << endl;
  // hash to scalar to parameter
  unsigned char hn_rG_skV_b[crypto_core_ed25519_SCALARBYTES];
  hash_to_scalar(hn_rG_skV_b, rG_skV_b, crypto_core_ed25519_SCALARBYTES);
  // get one time secret key by perform scalar addition with scalar_skS_b
  unsigned char one_time_address_secret_key[crypto_core_ed25519_SCALARBYTES];
  unsigned char scalar_skS_b[crypto_core_ed25519_SCALARBYTES];
  extract_scalar_from_sk(scalar_skS_b, skS_b); // extract the sk
  crypto_core_ed25519_scalar_add(one_time_address_secret_key, scalar_skS_b,
                                 hn_rG_skV_b);

  // can this sclar mult to stealth address
  unsigned char test_one_time_key_address[crypto_core_ed25519_BYTES];
  crypto_scalarmult_ed25519_base_noclamp(test_one_time_key_address,
                                         one_time_address_secret_key);
  cout << "Compare stealth address with computed from secret key of receiver" << endl;
  compare_byte(test_one_time_key_address, stealth_address, crypto_core_ed25519_BYTES);
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
  // the secretkeybyte is 64 bytes long, the first 32 byte is replaced with seed
  // and the next 32 byte is replaced with public key
  unsigned char skV_b[crypto_sign_SECRETKEYBYTES];
  unsigned char pkV_b[crypto_sign_PUBLICKEYBYTES];
  unsigned char skS_b[crypto_sign_SECRETKEYBYTES];
  unsigned char pkS_b[crypto_sign_PUBLICKEYBYTES];

  // crypto_sign_seed_keypair(pkS_b, skS_b, seed_1);
  // crypto_sign_seed_keypair(pkV_b, skV_b,
  //                         seed_2); // the proper way is use hash_to_scalar
  //  calculate the skV_b from skS_b
  crypto_sign_keypair(pkS_b, skS_b);
  crypto_sign_keypair(pkV_b, skV_b);

  unsigned char r[crypto_core_ed25519_SCALARBYTES];

  unsigned char one_time_key_address[crypto_core_ed25519_BYTES];
  sender_compute_stealth_address_and_test(one_time_key_address, r, pkV_b,
                                          pkS_b);
  receiver_test_compute(skV_b, pkV_b, skS_b, pkS_b, r, one_time_key_address);
  
  test_scalar_arithmetic();
}
