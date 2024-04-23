import nacl.hash
import nacl.encoding
from nacl.bindings.crypto_scalarmult import crypto_scalarmult_base

def hash_to_point(data):
    """
    Hash data to a point on the Edwards25519 curve using SHA-512 and converting to a curve point.
    """
    # Hash the data using SHA-512
    hashed_data = nacl.hash.sha512(data, encoder=nacl.encoding.RawEncoder)
    
    # Use the first half of the hash as the seed to reduce biases (similar to Monero's approach)
    seed = hashed_data[:32]
    
    # Convert the seed to a point on the curve
    point = crypto_scalarmult_base(seed)
    
    return point

# Example usage
data = b"Example data for hashing to a point on Edwards25519"
point = hash_to_point(data)
print("Point on Edwards25519:", point.hex())
