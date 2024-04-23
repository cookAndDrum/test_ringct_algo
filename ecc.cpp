#include <iostream>
#include <sodium.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sstream>
#include <string>

#define MESSAGE ((const unsigned char *)"Arbitrary data to hash")
#define MESSAGE_LEN 22

using namespace std;

string to_string(unsigned char *key, size_t n) {
  ostringstream out;
  for (size_t i = 0; i < n; i++)
    out << hex << int(key[i]);
  return out.str();
}

void hash_to_point(unsigned char *Hp, size_t hash_size, unsigned char *Hp_point,
                   size_t point_size) {
  // generate hash with generic hash from libsodium not keccak
  crypto_generichash(Hp, hash_size, MESSAGE, MESSAGE_LEN, NULL, 0);

  cout << "Generic hash size : " << hash_size << endl;
  cout << "Message: " << MESSAGE << endl;
  cout << "Message length: " << MESSAGE_LEN << endl;
  cout << "Generic hash: " << endl;

  string Hp_str = to_string(Hp, hash_size);
  cout << Hp_str << endl;

  // reset from hex
  cout << dec;
  cout << Hp_str.length() << endl;

  // map the hash to ed25519
  crypto_core_ed25519_from_hash(Hp_point, Hp);
  string Hp_point_hex = to_string(Hp_point, point_size);
  cout << "Point map to curve : " << Hp_point_hex << endl;
  cout << "Hex string length : " << Hp_point_hex.length() << endl;

  // check if valid
  cout << "Is this valid point on curve ? "
       << crypto_core_ed25519_is_valid_point(Hp_point) << endl;
}

// with keccak
void hash_to_point_v2() {}

void hash_to_scalar() {}

int main() {
  if (sodium_init() == -1) {
    return 1;
  }

  // prep hash to point
  unsigned char Hp[crypto_generichash_BYTES_MAX]; // hash output is 64 bytes
                                                  // long == 512 bit
  unsigned char
      Hp_point[crypto_core_ed25519_BYTES]; // byte for serialized point in curve
                                           // == 32 byte

  hash_to_point(Hp, crypto_generichash_BYTES_MAX, Hp_point,
                crypto_core_ed25519_BYTES);

  return 0;
}
