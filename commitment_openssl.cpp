#include <openssl/bn.h>
#include <openssl/ec.h>
#include <iostream>
#include <iomanip>
#include <sstream>

// Helper function to print a BIGNUM as hex
void print_hex(const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    std::cout << hex << std::endl;
    OPENSSL_free(hex);
}

int main()
{
    // Initialize context and BIGNUMs
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *test_a = BN_new();
    // EC_GROUP *group;

    // // Get the curve group for Ed25519 and its order
    // group = EC_GROUP_new_by_curve_name(NID_ed25519);
    // if (!group)
    // {
    //     std::cerr << "Failed to create curve group!" << std::endl;
    //     return 1;
    // }
    // const BIGNUM *order = EC_GROUP_get0_order(group);

    BIGNUM *order = BN_new();

    // Ed25519 curve order
    BN_hex2bn(&order, "1000000000000000000000000000000013E974E72F8A6922031D2603CFE0D7");

    // Generate random a and b, reduce them modulo the order
    BN_rand_range(a, order);
    BN_rand_range(b, order);

    // c = (a - b) mod order
    BN_mod_sub(c, a, b, order, ctx);

    // Print a, b, c
    print_hex(a);
    print_hex(b);
    print_hex(c);

    // test_a = (c + b) mod order
    BN_mod_add(test_a, c, b, order, ctx);

    // Print test_a
    print_hex(test_a);

    // Cleanup
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(test_a);
    // EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}
