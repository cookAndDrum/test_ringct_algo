#include <cstring>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_ed25519.h>

#define H_String        \
  ((const unsigned char \
        *)"This is used as H string generation, no one knows this secret")
#define H_Len 61

using namespace std;

void generate_H(unsigned char *H)
{
  unsigned char hash[crypto_generichash_BYTES];
  unsigned char str_to_hash[H_Len + 4];
  memmove(str_to_hash, "HSTR", 4); //  domain separation
  memmove(str_to_hash + 4, H_String, H_Len);

  crypto_generichash(hash, crypto_generichash_BYTES, H_String, H_Len, NULL, 0);

  crypto_core_ed25519_from_uniform(H, hash); // guarantee on main subgroup
  int is_success = crypto_core_ed25519_is_valid_point(
      H); // unnecessary, but to remind. Check on main subgroup, and dont have a
          // small order
  if (is_success != 1)
    exit(1);
}

// aGbH, where a and b are scalar, and G is the base point and B is the point
void add_key(unsigned char *aGbH, unsigned char *a, unsigned char *b,
             unsigned char *H)
{
  unsigned char aG[crypto_scalarmult_ed25519_BYTES];
  unsigned char bH[crypto_scalarmult_ed25519_BYTES];

  // check value, skip for now

  int is_success_aG = crypto_scalarmult_ed25519_base_noclamp(aG, a);
  int is_success_bH = crypto_scalarmult_ed25519_noclamp(bH, b, H);
  if (is_success_aG != 0 || is_success_bH != 0)
    cout << "scalar multiplication fail on aG or bH" << endl;

  int is_success_add = crypto_core_ed25519_add(aGbH, aG, bH);
  if (is_success_add != 0)
    cout << "point addition aG + bH fail due to invalid points" << endl;
}

void scenario_1(const unsigned char *H)
{
  // Scenario 1 : sender got one input, 2 output (ignore pseudo out for now)
  int input_1 = 10; // sender input
  int output_1 = 2; // recipient receive
  int change = 8;   // sender's change

  // sender side
  unsigned char a[crypto_core_ed25519_SCALARBYTES];
  unsigned char b1[crypto_core_ed25519_SCALARBYTES];
  unsigned char b2[crypto_core_ed25519_SCALARBYTES];

  crypto_core_ed25519_random(b1);
  crypto_core_ed25519_random(b2); // random scalar
  crypto_core_ed25519_scalar_add(a, b2, b1);

  // test a = b1 + b2
  unsigned char test_b1[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_sub(test_b1, a, b2);

  cout << "scalar byte length in byte : " << crypto_core_ed25519_SCALARBYTES
       << endl;

  cout << "a hex : " << endl;
  for (unsigned char c : b1)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << endl;
  cout << "test_a hex : " << endl;
  for (unsigned char c : test_b1)
    cout << hex << setw(2) << setfill('0') << int(c);
  cout << dec << endl;

  if (memcmp(b1, test_b1, crypto_scalarmult_ed25519_SCALARBYTES) == 0)
    cout << "a and test_a are equal" << endl;
  else
    cout << "a and test_a are not equal" << endl;
}

void print_hex(const unsigned char *key, size_t n)
{
  for (size_t i = 0; i < n; i++)
    cout << hex << setw(2) << setfill('0') << int(key[i]);
  cout << dec << endl;
}

int main()
{
  if (sodium_init() == -1)
    return 1;

  // generate H. H should be storing in the code base somewhere to reduce
  // overhead
  unsigned char H[crypto_core_ed25519_BYTES]; // suppose to store this
  generate_H(H);

  // scenario_1(H);

  unsigned char a[crypto_core_ed25519_SCALARBYTES];
  unsigned char b[crypto_core_ed25519_SCALARBYTES];
  unsigned char c[crypto_core_ed25519_SCALARBYTES];

  crypto_core_ed25519_random(a);
  crypto_core_ed25519_random(b);

  crypto_core_ed25519_scalar_sub(c, a, b);

  print_hex(a, crypto_core_ed25519_SCALARBYTES);
  print_hex(b, crypto_core_ed25519_SCALARBYTES);
  print_hex(c, crypto_core_ed25519_SCALARBYTES);

  // test
  unsigned char test_a[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_add(test_a, c, b);
  print_hex(test_a, crypto_core_ed25519_SCALARBYTES);

  return 0;
}
