import hashlib
import ecdsa
import base58

decimal_number = 103777038173331618261831207697011014430541611824708718690192712692106013982392

def generate_keys_from_private():
    # --------- Chave Privada → WIF ---------
    prefix = b'\x80'
    private_key_bytes = decimal_number.to_bytes(32, 'big')
    extended_key = prefix + private_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode()

    # --------- Gerar chave pública comprimida ---------
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix_pub = b'\x02' if y % 2 == 0 else b'\x03'
    public_key_compressed = prefix_pub + x.to_bytes(32, 'big')

    # --------- Gerar endereço Bitcoin (P2PKH) ---------
    sha256_pubkey = hashlib.sha256(public_key_compressed).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pubkey).digest()
    mainnet_prefix = b'\x00'
    payload = mainnet_prefix + ripemd160
    checksum_addr = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum_addr).decode()

    return {
        'private_key_wif': wif,
        'address': address
    }

result = generate_keys_from_private()

print("Endereço Bitcoin (P2PKH):", result['address'])
print("Chave privada (WIF):", result['private_key_wif'])