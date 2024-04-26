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
    oss << hex << int(key[i]);
  }
}

void fill_seed(int val, unsigned char *seed, size_t n) {
  for (size_t i = 0; i < n; i++)
    seed[i] = val;
}

// to test if the operation is correct (of the libsodium)
// extract the seed from sk, sk (64 byte) is composed of first 32byte as seed,
// next 32 byte as pk
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
  unsigned char one_time_key_address[crypto_core_ed25519_BYTES];
  is_success =
      crypto_core_ed25519_add(one_time_key_address, G_hn_r_pkV_b, pkS_b);
  if (is_success != 0)
    cout << "Point addition for one time address fail due to invalid point"
         << endl;

  ////////////////////////////////////////////////////////////////////////////
  // test
  // test if r * skV_b * G == r * pkV_b
  unsigned char test_pkV_b[crypto_sign_PUBLICKEYBYTES];
  cout << "lenght of secret key byte: " << crypto_sign_SECRETKEYBYTES << endl;

  unsigned char copied_pkV_b_from_sk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char scalar_skV_b[32];
  unsigned char copied_seed_skV_b[crypto_sign_ed25519_SEEDBYTES];
  memcpy(copied_pkV_b_from_sk, skV_b + crypto_sign_ed25519_SEEDBYTES,
         32); // clone the pk from sk
  memcpy(copied_seed_skV_b, skV_b,
         crypto_sign_ed25519_SEEDBYTES); // clone the pk from sk
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

  cout << "===============================" << endl;

  // test if K_o - Hn(rG*skV_b) * G = pkS_b
  unsigned char rG[crypto_core_ed25519_BYTES]; // given by the sender
  crypto_scalarmult_ed25519_base_noclamp(rG, r);

  unsigned char rG_skV_b[crypto_core_ed25519_BYTES];
  is_success = crypto_scalarmult_ed25519(rG_skV_b, scalar_skV_b, rG);
  if (is_success != 0)
    cout << "Scalar operation failure in rG_skV_b." << endl;

  cout << "Test for r_pkV_b: " << endl;
  for (unsigned char c : r_pkV_b)
    cout << hex << int(c);
  cout << endl;

  cout << "Test for rG_skV_b: " << endl;
  for (unsigned char c : rG_skV_b)
    cout << hex << int(c);
  cout << dec << endl;

  if (memcmp(r_pkV_b, rG_skV_b, crypto_core_ed25519_BYTES) == 0)
    cout << "The scalar output are equal " << endl;
  else
    cout << "The scalar output are not equal. " << endl;

  unsigned char hn_rG_skV_b[crypto_core_ed25519_SCALARBYTES];
  hash_to_scalar(hn_rG_skV_b, rG_skV_b, crypto_core_ed25519_SCALARBYTES);
  unsigned char G_hn_rG_skV_b[crypto_core_ed25519_BYTES];
  is_success =
      crypto_scalarmult_ed25519_base_noclamp(G_hn_rG_skV_b, hn_rG_skV_b);
  if (is_success != 0)
    cout << "Scalar operation failure in rG_skV_b." << endl;

  if (memcmp(G_hn_r_pkV_b, G_hn_rG_skV_b, crypto_core_ed25519_BYTES) == 0)
    cout << "The scalar mult on Hn is equal " << endl;
  else
    cout << "The scalar mult on Hn is not equal. " << endl;

  unsigned char test_pkV_b_subtract[crypto_core_ed25519_BYTES];
  crypto_core_ed25519_sub(test_pkV_b_subtract, one_time_key_address,
                          G_hn_rG_skV_b);

  cout << "Test for pkS_b: " << endl;
  for (unsigned char c : pkS_b)
    cout << hex << int(c);
  cout << endl;

  cout << "Test for test_pkV_b_subtract from one time key address: " << endl;
  for (unsigned char c : test_pkV_b_subtract)
    cout << hex << int(c);
  cout << endl;

  if (memcmp(pkS_b, test_pkV_b_subtract, crypto_core_ed25519_BYTES) == 0)
    cout << "The public spending key compare is equal " << endl;
  else
    cout << "The public spending key is not equal. " << endl;

  cout << "===============================" << endl;

  // test from sender generated subtraction
  unsigned char test_one_time_key_sub_sender[crypto_core_ed25519_BYTES];
  crypto_core_ed25519_sub(test_one_time_key_sub_sender, one_time_key_address,
                          G_hn_r_pkV_b);

  cout << "Test for sender side one time key address subtraction: " << endl;
  for (unsigned char c : test_one_time_key_sub_sender)
    cout << hex << int(c);
  cout << dec << endl;

  if (memcmp(test_one_time_key_sub_sender, pkS_b, crypto_core_ed25519_BYTES) ==
      0)
    cout << "Sender side sub is exactly same as pkS_b" << endl;
  else
    cout << "Sender side sub is different as pkS_b" << endl;

  cout << "===============================" << endl;

  // test receiver compute secret key for one time address
  // how to add up two scalar together ??
  unsigned char one_time_address_secret_key[crypto_core_ed25519_SCALARBYTES];
  unsigned char copied_seed_skS_b[crypto_sign_ed25519_SEEDBYTES];
  unsigned char scalar_skS_b[crypto_core_ed25519_SCALARBYTES];
  memcpy(copied_seed_skS_b, skS_b,
         crypto_sign_ed25519_SEEDBYTES); // clone the pk from sk
  extract_scalar_from_sk(scalar_skS_b, copied_seed_skS_b); // extract the sk
  crypto_core_ed25519_scalar_add(one_time_address_secret_key, scalar_skS_b,
                                 hn_rG_skV_b);

  // test is same one time key address
  unsigned char test_one_time_key_address[crypto_core_ed25519_BYTES];
  crypto_scalarmult_ed25519_base_noclamp(test_one_time_key_address,
                                         one_time_address_secret_key);

  cout << "Test for one time key address: " << endl;
  for (unsigned char c : one_time_key_address)
    cout << hex << int(c);
  cout << endl;

  cout << "Test for computed one time key from secret key: " << endl;
  for (unsigned char c : test_one_time_key_address)
    cout << hex << int(c);
  cout << endl;

  if (memcmp(one_time_key_address, test_one_time_key_address,
             crypto_core_ed25519_BYTES) == 0)
    cout << "The one time key address compare is equal " << endl;
  else
    cout << "The one time key address is not equal. " << endl;

  cout << "===============================" << endl;
  unsigned char test_hn_rG_skV_b[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_sub(test_hn_rG_skV_b, one_time_address_secret_key, scalar_skS_b);

  cout << "test the scalar sub of lsodium : one time address secret key - scalar_skS_b" << endl;
  for (unsigned char c : test_hn_rG_skV_b)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;
  for (unsigned char c : hn_rG_skV_b)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;

  cout << "===============================" << endl;
  unsigned char A[crypto_core_ed25519_SCALARBYTES];
  unsigned char B[crypto_core_ed25519_SCALARBYTES];
  unsigned char C[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_random(B);
  crypto_core_ed25519_scalar_random(C);
  crypto_core_ed25519_scalar_add(A, B, C);
  cout << "test the scalar sub of lsodium : non-reduced random byte(suppose reduce beforehand) " << endl;
  unsigned char test_C[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_add(test_C, A, B);

  cout << "C " << endl;
  for (unsigned char c : C)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;
  cout << "test_C " << endl;
  for (unsigned char c : test_C)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;
  
  cout << "test the scalar sub of lsodium : reduced random byte " << endl;
  unsigned char reduce_A[crypto_core_ed25519_SCALARBYTES];
  unsigned char reduce_B[crypto_core_ed25519_SCALARBYTES];
  unsigned char reduce_C[crypto_core_ed25519_SCALARBYTES];
  unsigned char reduce_reduce_C[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_reduce(reduce_B, B);
  crypto_core_ed25519_scalar_reduce(reduce_C, C);
  crypto_core_ed25519_scalar_reduce(reduce_reduce_C, reduce_C);

  cout << "reduce C " << endl;
  for (unsigned char c : reduce_C)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;


  cout << "===============================" << endl;

  // test the scalar add of libsodium and openssl would result the same stealth
  // address secret key
  BIGNUM *o_scalar_skS_b = BN_new();
  BIGNUM *o_hn_rG_skV_b = BN_new();
  BIGNUM *order = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_hex2bn(&order,
            "1000000000000000000000000000000013E974E72F8A6922031D2603CFE0D7");

  BN_bin2bn(scalar_skS_b, 32, o_scalar_skS_b);
  BN_bin2bn(hn_rG_skV_b, 32, o_hn_rG_skV_b);

  // test if the conversion between lsodium and openssl correct
  char *o_scalar_skS_b_hex = BN_bn2hex(o_scalar_skS_b);
  char *o_hn_rG_skV_b_hex = BN_bn2hex(o_hn_rG_skV_b);
  cout << "o_scalar_skS_b_hex " << endl;
  cout << o_scalar_skS_b_hex << endl;

  cout << "scalar_skS_b from lsodium" << endl;
  for (unsigned char c : scalar_skS_b)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;

  cout << "o_hn_rG_skV_b_hex " << endl;
  cout << o_hn_rG_skV_b_hex << endl;

  cout << "hn_rG_skV_b from lsodium" << endl;
  for (unsigned char c : hn_rG_skV_b)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;

  // test addition
  //crypto_core_ed25519_scalar_add(one_time_address_secret_key, scalar_skS_b,
  //                               hn_rG_skV_b);
  BIGNUM *o_one_time_secret_key = BN_new();
  BN_mod_add(o_one_time_secret_key, o_scalar_skS_b, o_hn_rG_skV_b, order, ctx);
  char *o_one_time_secret_key_hex = BN_bn2hex(o_one_time_secret_key);
  cout << "o_one_time_secret_key_hex " << endl;
  cout << o_one_time_secret_key_hex  << endl;

  cout << "one time secret key from lsodium" << endl;
  for (unsigned char c : one_time_address_secret_key)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;

  delete[] o_hn_rG_skV_b_hex;
  delete[] o_scalar_skS_b_hex;
  delete[] o_one_time_secret_key_hex;
  BN_free(o_scalar_skS_b);
  BN_free(o_hn_rG_skV_b);
  BN_free(order);
  BN_free(o_one_time_secret_key);
  BN_CTX_free(ctx);

  return 0;
}
