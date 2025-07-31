import base58
import hashlib
from ecdsa import SigningKey, SECP256k1

wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3r6gP3YZUceJoiXDL3sSX"

def wif_to_private_key(wif_key):
    try:
        # Decodifica usando Base58Check
        decoded = base58.b58decode_check(wif_key)
    except ValueError as e:
        print(f"Erro ao decodificar WIF: {e}")
        return None, None

    # Verifica prefixo
    if decoded[0] != 0x80:
        print("Prefixo inválido. Não é uma chave WIF padrão da mainnet Bitcoin.")
        return None, None

    compressed = False
    # Checa se é chave comprimida (sufixo 0x01)
    if len(decoded) == 34 and decoded[-1] == 0x01:
        key_bytes = decoded[1:-1]  # Remove prefixo e sufixo
        compressed = True
    elif len(decoded) == 33:
        key_bytes = decoded[1:]  # Remove prefixo
    else:
        print("Formato de chave inválido.")
        return None, None

    return key_bytes, compressed

def private_key_to_public_key(private_key_bytes, compressed=True):
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key

    if compressed:
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        public_key = prefix + x.to_bytes(32, 'big')
    else:
        public_key = b'\x04' + vk.to_string()

    return public_key

def public_key_to_address(public_key_bytes):
    sha256 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    # Mainnet prefix
    prefixed = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    address_bytes = prefixed + checksum
    address = base58.b58encode(address_bytes).decode()
    return address

if __name__ == "__main__":
    private_key_bytes, compressed = wif_to_private_key(wif)
    
    if private_key_bytes:
        key_int = int.from_bytes(private_key_bytes, byteorder='big')
        public_key = private_key_to_public_key(private_key_bytes, compressed)
        address = public_key_to_address(public_key)
        print(f"Chave privada (decimal): {key_int}")
        print(f"Chave privada (hex): {private_key_bytes.hex()}")
        print(f"Chave privada (endereço): {address}")
