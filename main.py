# Samantha Deshazer   / RSA  / Python 3
import math
import random
import sys
import time

publicKey = 65537


def isPrime(num):  # rabinMiller helper function
    n = num
    n = n - 1
    r = 0  # remainder
    while n % 2 == 0:
        n = n / 2
        r += 1
    n = int(n)  # rounding
    rand = random.randrange(2, num - 1)
    result = exponentiate(rand, n, num)
    if result == 1 or result == (num - 1):
        return True
    i = 0
    while i < r:
        rand = exponentiate(2, (2 ** i) * n, num)
        if rand == (num - 1):
            return True
        i += 1
    return False


def rabinMiller(possiblePrime, k):
    for i in range(k):
        if not isPrime(possiblePrime):
            return False
    return True


def exponentiate(a, b, c):
    result = 1
    a = a % c
    while b > 0:
        if b & 1:
            result = (result * a) % c
        b = b >> 1
        a = (a * a) % c
    return result


# 16 bit primes:
def genPrime():
    prime = random.getrandbits(16)
    while not (rabinMiller(prime,
                           50) and prime % 12 == 5):  # make sure our random number is prime and congruent to 5 mod 12
        prime = random.getrandbits(16)
        if (prime % 2) == 0:
            prime += 1
    return prime


# 32 bit hash adapted from wiki:
def elfHash(message):
    hash = 0
    for char in message:
        hash = (hash << 4) + ord(char)
        result = (hash & 0xF0000000)
        if result != 0:
            hash = hash ^ (result >> 24)
        hash = hash & ~result
    return hash


# from wiki extended gcd
def genKeysXGCD(phi, publicKey):
    olT = 0
    t = 1
    oldR = publicKey
    r = phi
    while r != 0:
        quotient = oldR // r
        (olT, t) = (t, olT - quotient * t)
        (oldR, r) = (r, oldR - quotient * r)
    if oldR > 1:
        return -1
    if olT < 0:
        olT = olT + publicKey
    return olT


def genModulus(p, q):
    return p * q


def getInput():
    for lineRead in sys.stdin:
        return lineRead


# the longest method in this is handling standard input:
def input():
    print("example: sig sign message", "sig verify <modulus> message <message signature>")
    line = getInput()
    i = 0
    mode, message, modulus, signature = "", "", "", ""
    inputs = line.split()
    if len(inputs) >= 2:
        for item in inputs:
            if i == 0:
                if item != "sig":
                    sys.exit(0)
            if i == 1:
                mode = item
                if (not isModeVerify(mode)) & (not isModeSign(mode)):
                    sys.exit(0)
            if i == 2:
                if isModeSign(mode):
                    message = item
                elif isModeVerify(mode):
                    modulus = item
                else:
                    print("no valid mode entered, mode entered:", mode)
                    print("aborting")
                    sys.exit(0)
            if i == 3:
                if isModeSign(mode):
                    break
                if isModeVerify(mode):
                    message = item
            if i == 4:
                if isModeVerify(mode):
                    signature = item
                    break
            i += 1
        checkInputAndExecute(mode, message, modulus, signature)
    else:
        print("Error: incorrect number of arguments")


# en = hash^(e) mod n
def encrypt(hash, e, n):
    return exponentiate(hash, e, n)


# The general piecing together of everything is here:
def checkInputAndExecute(mode, message, modulus, signature):
    # sign mode: // TODO get rid of spaces on input
    if isModeSign(mode):
        hash = elfHash(message)  # message is hashed
        p = genPrime()  # generate primes
        q = genPrime()
        n = genModulus(p, q)
        t = (p - 1) * (q - 1)
        e = genKeysXGCD(publicKey, t) # generate the key based on PK and T
        en = encrypt(hash, e, n)
        print("p : ", hex(p), "q : ", hex(q), "n :", hex(n), "t :", hex(t))
        print("message hashed : ", hex(hash))
        print(" signing with e(private key) : ", hex(e))
        print("Signature : ", hex(en))
        print("complete output for verification:")
        print(hex(n),message,hex(en))

    # verify mode:
    if isModeVerify(mode):
        verifySignature(int(modulus, 16), message, int(signature, 16))


def verifySignature(modulus, message, signature):
    hash = elfHash(message)
    de = encrypt(signature, publicKey, modulus)
    if de == hash:
        print("!!! message is verified !!!")
        return True
    print("!!! message is forged !!!")
    return False


def isModeSign(mode):
    if mode == "sign":
        return True
    return False


def isModeVerify(mode):
    if mode == "verify":
        return True
    return False


if __name__ == '__main__':
    while True:
        input()
