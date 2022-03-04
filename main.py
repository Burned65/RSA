import hashlib
import math
import random


def miller_rabin(n):
    m = 0
    for k in range(1, n):
        m = (n-1)//2**k
        if m % 2 == 1:
            break
    a = random.randint(2, n-1)
    b = pow(a, m, n)
    if b % n == 1:
        return True
    for i in range(1, k+1):
        if b % n == n-1:
            return True
        else:
            b = pow(b, 2, n)
    return False


def square_multiply(x, m, n):
    y = 1
    r = m.bit_length()
    for i in range(0, r):
        if m % 2 == 1:
            y = y * x % n
        x = pow(x, 2, n)
        m = m >> 1
    return y


def euclidean_algorithm(a, b):
    k, r0, r1, s0, s1, t0, t1 = 0, a, b, 1, 0, 0, 1

    while True:
        k += 1
        qk = r0 // r1
        r2 = r0 - qk * r1
        s2 = s0 - qk * s1
        t2 = t0 - qk * t1

        r0, r1 = r1, r2
        s0, s1 = s1, s2
        t0, t1 = t1, t2

        if r2 == 0:
            return r0, s0, t0


def encrypt(x, e, n):
    return square_multiply(x, e, n)


def decrypt(y, d, n):
    return square_multiply(y, d, n)


def calculate_d(p, q, e):
    phi_of_n = (p-1) * (q-1)
    a, b, c = euclidean_algorithm(e, phi_of_n)
    return b + phi_of_n


def generate_prime():
    list_of_primes = [1, 7, 11, 13, 17, 19, 23, 29]
    z = random.randint(2**2000, 2**2001-1)
    p = 30 * z
    is_prime = False
    for i in range(200):
        for j in list_of_primes:
            n = p + j + i * 30
            for k in range(50):
                is_prime = miller_rabin(n)
                if not is_prime:
                    break
            if is_prime:
                return n


def difference_of_squares(n):
    u = math.ceil(math.sqrt(n))
    while not is_square(u**2 - n):
        u += 1
    w = int(math.sqrt(u**2 - n))
    return u + w, u - w


def is_square(number):
    if number < 0:
        return False
    else:
        return int(math.sqrt(number)) ** 2 == number


def mgf1(seed: bytes, l, hash_function):
    counter = 0
    t = bytearray()
    while True:
        counter += 1
        c = counter.to_bytes(4, 'big')
        t += hash_function(seed + c).digest()
        if len(t) > l:
            return t[0:l]


def transform_oaep(hash_function, n, m):
    if not len(m) <= len(n.to_bytes((n.bit_length() + 7) // 8, 'big')) - 2 * \
            hash_function().digest_size - 2:
        raise ValueError(f"{m = } too long.")
    one_byte = 0b1.to_bytes(1, 'big')
    l = bytearray()
    l_hash = hash_function(l).digest()

    seed = random.randint(0, 2**(hash_function().digest_size*8)-1)
    seed = seed.to_bytes(hash_function().digest_size, 'big')

    length_ps = len(n.to_bytes((n.bit_length() + 7) // 8, 'big')) - len(m) - 2*hash_function().digest_size - 2
    ps = bytearray(length_ps)

    mgf_seed = mgf1(seed, hash_function().digest_size + len(ps) + len(one_byte) + len(m), hash_function)
    masked_db = xor_bytes(mgf_seed, l_hash + ps + one_byte + m)

    mgf_masked_db = mgf1(masked_db, len(seed), hash_function)
    masked_seed = xor_bytes(mgf_masked_db, seed)

    return bytearray(1) + masked_seed + masked_db


def reverse_oaep(transformed, hash_function):
    masked_seed = transformed[1:hash_function().digest_size + 1]
    masked_db = transformed[hash_function().digest_size + 1::]

    mgf_db = mgf1(masked_db, hash_function().digest_size, hash_function)
    seed = xor_bytes(mgf_db, masked_seed)

    mgf_seed = mgf1(seed, len(masked_db), hash_function)
    db = xor_bytes(mgf_seed, masked_db)

    ps_01_m = db[hash_function().digest_size::]
    m = remove_0_and_1_bytes(ps_01_m)
    return m


def remove_0_and_1_bytes(byte):
    for i, item in enumerate(byte):
        if item == 1:
            return byte[i+1::]


def xor_bytes(byte1, byte2):
    if len(byte1) != len(byte2):
        raise ValueError("Arrays need to be the same size")
    result = bytearray(len(byte1))
    for i, item in enumerate(byte1):
        result[i] = byte1[i] ^ byte2[i]
    return result


def oaep():
    message = "test"
    message_bytes = bytearray(message.encode())
    print(f"original message: {message}")
    p = generate_prime()
    q = generate_prime()
    e = 53
    d = calculate_d(p, q, e)
    n = p*q
    transformed = transform_oaep(hashlib.sha256, n, message_bytes)
    print(f"transformed message: {transformed}")
    encrypted = encrypt(int(transformed.hex(), 16), e, n)
    print(f"encrypted message: {encrypted}")
    decrypted = decrypt(encrypted, d, n)
    m = reverse_oaep(bytearray(1) + decrypted.to_bytes((decrypted.bit_length() + 7) // 8, 'big'), hashlib.sha256)
    print(f"reverse transformed message: {m.decode()}")


if __name__ == '__main__':
    """p, q = 7, 11
    n = int(p * q)
    e = 53
    d = calculate_d(p, q, e)
    print(f"{d = }")
    x = 30
    y = encrypt(x, e, n)
    print(f"encrypted: {y = }")
    x = decrypt(y, d, n)
    print(f"decrypted: {x = }")"""
    # print(difference_of_squares(20353*41851))
    oaep()
