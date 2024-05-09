#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/utils.h>

#define H_String        \
  ((const unsigned char \
        *)"This is used as H string generation, no one knows this secret")
#define H_Len 61

using namespace std;

void to_string(string *output, unsigned char *key, size_t n)
{
  ostringstream oss;
  for (size_t i = 0; i < n; i++)
  {
    oss << hex << setw(2) << setfill('0') << int(key[i]);
  }
}

void print_hex(const unsigned char *key, size_t n)
{
  for (size_t i = 0; i < n; i++)
  {
    cout << hex << setw(2) << setfill('0') << int(key[i]);
  }
  cout << endl;
}

void compare_byte(const unsigned char *a, const unsigned char *b, size_t n)
{
  if (memcmp(a, b, n) == 0)
    cout << "Both byte strings equal" << endl;
  else
    cout << "WARNING>> Both byte strings are not equal" << endl;
}

// input long long is guaranteed at least 64bit == 8 byte, output in little endian
void int_to_scalar_byte(unsigned char *out, long long input)
{
  memset(out, 0, crypto_core_ed25519_SCALARBYTES); // use 32 byte for now, if to use 8 byte, probably need to come up with own scalar multiplication funciton
  // overflow if > 32 byte, but not possible
  memcpy(out, &input, sizeof(input));
}

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
void add_key(unsigned char *aGbH, const unsigned char *a, const unsigned char *b,
             const unsigned char *H)
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
  // check equality of scalar addition and point addition
  unsigned char x[crypto_core_ed25519_SCALARBYTES];
  unsigned char y1[crypto_core_ed25519_SCALARBYTES];
  unsigned char y2[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_random(y1);
  crypto_core_ed25519_scalar_random(y2); // random scalar
  // a = b1 + b2
  crypto_core_ed25519_scalar_add(x, y2, y1);

  // test a = b1 + b2 mod l
  unsigned char test_y1[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_sub(test_y1, x, y2);
  cout << "y1 hex : " << endl;
  print_hex(y1, crypto_core_ed25519_SCALARBYTES);
  cout << "test_y1 hex : " << endl;
  print_hex(test_y1, crypto_core_ed25519_SCALARBYTES);
  compare_byte(y1, test_y1, crypto_core_ed25519_SCALARBYTES);
  cout << "==========================================" << endl;

  // compute commitment
  //  check if xG = y1G + y2G
  unsigned char xG[crypto_core_ed25519_BYTES];
  unsigned char y1G[crypto_core_ed25519_BYTES];
  unsigned char y2G[crypto_core_ed25519_BYTES];
  unsigned char y1G_y2G[crypto_core_ed25519_BYTES];
  crypto_scalarmult_ed25519_base_noclamp(xG, x);   // using noclamp as not missing any bit
  crypto_scalarmult_ed25519_base_noclamp(y1G, y1); // using noclamp as not missing any bit
  crypto_scalarmult_ed25519_base_noclamp(y2G, y2); // using noclamp as not missing any bit

  crypto_core_ed25519_add(y1G_y2G, y1G, y2G);
  cout << "xG hex : " << endl;
  print_hex(xG, crypto_core_ed25519_BYTES);
  cout << "y1G + y2G hex : " << endl;
  print_hex(y1G_y2G, crypto_core_ed25519_BYTES);
  compare_byte(xG, y1G_y2G, crypto_core_ed25519_SCALARBYTES);
}

// test complete commitment calculation
void scenario_2(const unsigned char *H)
{
  cout << "==========================================" << endl;
  cout << "==========================================" << endl;
  cout << "Scenario 2" << endl;
  // Scenario 2 : sender got one input, 2 output (ignore pseudo out for now)
  int input_1 = 10; // sender input
  int output_1 = 2; // recipient receive
  int change = 8;   // sender's change

  unsigned char input_1_scalar[crypto_core_ed25519_SCALARBYTES];
  unsigned char output_1_scalar[crypto_core_ed25519_SCALARBYTES];
  unsigned char change_scalar[crypto_core_ed25519_SCALARBYTES];
  int_to_scalar_byte(input_1_scalar, input_1);
  int_to_scalar_byte(output_1_scalar, output_1);
  int_to_scalar_byte(change_scalar, change);

  // print out all scalars
  cout << "input_1 hex : " << endl;
  print_hex(input_1_scalar, crypto_core_ed25519_SCALARBYTES);
  cout << "output_1 hex : " << endl;
  print_hex(output_1_scalar, crypto_core_ed25519_SCALARBYTES);
  cout << "change hex : " << endl;
  print_hex(change_scalar, crypto_core_ed25519_SCALARBYTES);

  // test input 1 = output 1 + change
  unsigned char test_input_1_scalar[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_add(test_input_1_scalar, output_1_scalar, change_scalar);
  cout << "test input 1 hex : " << endl;
  print_hex(test_input_1_scalar, crypto_core_ed25519_SCALARBYTES);

  // test if aH = b1H + b2H
  unsigned char aH[crypto_core_ed25519_BYTES];     // input 1
  unsigned char b1H[crypto_core_ed25519_BYTES];    // output 1
  unsigned char b2H[crypto_core_ed25519_BYTES];    // change
  unsigned char b1_b2H[crypto_core_ed25519_BYTES]; // output 1 + change

  crypto_scalarmult_ed25519_noclamp(aH, input_1_scalar, H);
  crypto_scalarmult_ed25519_noclamp(b1H, output_1_scalar, H);
  crypto_scalarmult_ed25519_noclamp(b2H, change_scalar, H);

  crypto_core_ed25519_add(b1_b2H, b1H, b2H);
  cout << "aH hex : " << endl;
  print_hex(aH, crypto_core_ed25519_BYTES);
  cout << "b1H + b2H hex : " << endl;
  print_hex(b1_b2H, crypto_core_ed25519_BYTES);

  cout << "==========================================" << endl;

  // Prep blinding factor
  unsigned char x[crypto_core_ed25519_SCALARBYTES];
  unsigned char y1[crypto_core_ed25519_SCALARBYTES];
  unsigned char y2[crypto_core_ed25519_SCALARBYTES];
  crypto_core_ed25519_scalar_random(y1);
  crypto_core_ed25519_scalar_random(y2); // random scalar
  crypto_core_ed25519_scalar_add(x, y2, y1);
  unsigned char xG[crypto_core_ed25519_BYTES];
  unsigned char y1G[crypto_core_ed25519_BYTES];
  unsigned char y2G[crypto_core_ed25519_BYTES];
  crypto_scalarmult_ed25519_base_noclamp(xG, x);   // using noclamp as not missing any bit
  crypto_scalarmult_ed25519_base_noclamp(y1G, y1); // using noclamp as not missing any bit
  crypto_scalarmult_ed25519_base_noclamp(y2G, y2); // using noclamp as not missing any bit

  // caclulate pseudo output and output commitment
  unsigned char pseudo_output[crypto_core_ed25519_BYTES];
  unsigned char output_1_commitment[crypto_core_ed25519_BYTES];
  unsigned char change_commitment[crypto_core_ed25519_BYTES];

  // pseudo output = xG + aH
  crypto_core_ed25519_add(pseudo_output, xG, aH);
  // output commitment = y1G + b1H
  crypto_core_ed25519_add(output_1_commitment, y1G, b1H);
  // change commitment = y2G + b2H
  crypto_core_ed25519_add(change_commitment, y2G, b2H);

  cout << "pseudo output hex : " << endl;
  print_hex(pseudo_output, crypto_core_ed25519_BYTES);
  cout << "output 1 hex : " << endl;
  print_hex(output_1_commitment, crypto_core_ed25519_BYTES);
  cout << "change commitment hex : " << endl;
  print_hex(change_commitment, crypto_core_ed25519_BYTES);

  cout << "==========================================" << endl;

  // test if pseudo output = output 1 + change
  unsigned char test_sum_output_commitment[crypto_core_ed25519_BYTES];
  crypto_core_ed25519_add(test_sum_output_commitment, output_1_commitment, change_commitment);
  cout << "sum output commitment hex : " << endl;
  print_hex(test_sum_output_commitment, crypto_core_ed25519_BYTES);
  compare_byte(pseudo_output, test_sum_output_commitment, crypto_core_ed25519_BYTES);

  cout << "==========================================" << endl;
  // test the function add key
  unsigned char xGaH[crypto_core_ed25519_BYTES];
  add_key(xGaH, x, input_1_scalar, H);
  cout << "test add key with xG + aH hex : " << endl;
  print_hex(xGaH, crypto_core_ed25519_BYTES);
  compare_byte(xGaH, pseudo_output, crypto_core_ed25519_BYTES);
}

int main()
{
  if (sodium_init() == -1)
    return 1;

  // generate H. H should be storing in the code base somewhere to reduce
  // overhead
  unsigned char H[crypto_core_ed25519_BYTES]; // suppose to store this somewhere in code (hard coded)
  generate_H(H);

  scenario_1(H);
  scenario_2(H);

  // test in to byte string
  // int num = 17;
  // unsigned char input_1[crypto_core_ed25519_SCALARBYTES];
  // cout << "Printing out test int to byte" << endl;
  // int_to_scalar_byte(input_1, num);
  // print_hex(input_1, crypto_core_ed25519_SCALARBYTES);
  return 0;
}
