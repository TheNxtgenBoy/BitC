from base58 import b58encode
from ecdsa import SigningKey, SECP256k1
from binascii import unhexlify, hexlify
from hashlib import sha256, new
from os import urandom
from requests import session

class BitC():
    def __init__(self):
        self.session = session()
        for loop in range(10000):
            print(f'Batch {loop+1} : ',end="")
            addrs, pkeys = [], []
            for _ in range(128):
                secret_exponent = urandom(32)
                pvt = sha256(secret_exponent).hexdigest()
                privatekey = unhexlify(pvt)
                s = SigningKey.from_string(privatekey, curve = SECP256k1)
                publickey = '04' + hexlify(s.verifying_key.to_string()).decode('utf-8')
                extended_key = "80"+pvt
                first_sha256 = sha256(unhexlify(extended_key)).hexdigest()
                second_sha256 = sha256(unhexlify(first_sha256)).hexdigest()
                final_key = extended_key+second_sha256[:8]
                WIF = b58encode(unhexlify(final_key))
                alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                c = '0'; byte = '00'; zero = 0
                var = new('ripemd160')
                var.update(sha256(unhexlify(publickey.encode())).digest())
                a = (byte + var.hexdigest())
                doublehash = sha256(sha256(unhexlify(a.encode())).digest()).hexdigest()
                address = a + doublehash[0:8]
                for char in address:
                    if (char != c):
                        break
                    zero += 1
                zero = zero // 2
                n = int(address, 16)
                output = []
                while (n > 0):
                    n, remainder = divmod (n, 58)
                    output.append(alphabet[remainder])
                count = 0
                while (count < zero):
                    output.append(alphabet[0])
                    count += 1
                addr = ''.join(output[::-1])
                addrs.append(addr)
                pkeys.append(WIF.decode('utf-8'))
            url = 'https://blockchain.info/balance?cors=true&active=' + ','.join(addrs)
            r = self.session.get(url).json()
            found = [(addrs[i], pkeys[i], r[addrs[i]]['final_balance']) for i in range(len(addrs)) if r[addrs[i]]['final_balance'] != 0]
            if len(found) != 0:
                [open('found.txt','a').write(f'{i[0]}\t{i[1]}\t{i[2]}\n') for i in found]
                print(f'Found {len(found)} !!!!!!')
                break
            else:print('Nothing Found', end=" - ")
            print(f'Scanned : {(loop+1)*128} wallets')

if __name__ == "__main__":
    BitC()