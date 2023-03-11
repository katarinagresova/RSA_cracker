import subprocess
import random
from collections import namedtuple
import sys
import secrets
import time
# import gmpy2
import argparse

GeneratedKeys = namedtuple('GeneratedKeys', ['p', 'q', 'n', 'e', 'd'])
CrackedKeys = namedtuple('CrackedKeys', ['p', 'q', 'm'])

def run_cmd(cmd):
    try:
      subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      return 0
    except Exception:
      return 1

def gen_keys(s, e, t= 60):
    bitlen = random.randrange(s, e, 1)
    output = subprocess.check_output(['./kry', '-g', str(bitlen)], timeout=t)
    assert output[-1] == 10 # check newline
    return (bitlen, GeneratedKeys(*output.strip().split()))

def encrypt(e, n, m, t = 60):
    output = subprocess.check_output(['./kry', '-e', e, n , m], timeout=t)
    assert output[-1] == 10 # check newline
    return output.strip()

def decrypt(d, n, c, t = 60):
    output = subprocess.check_output(['./kry', '-d', d, n , c], timeout=t)
    assert output[-1] == 10 # check newline
    return output.strip()

def crack(e, n, c, t = 60):
    output = subprocess.check_output(['./kry', '-b', e, n ,c], timeout=t)
    assert output[-1] == 10 # check newline
    return CrackedKeys(*output.strip().split())

def main():
    parser = argparse.ArgumentParser(description="RSA tester")
    parser.add_argument("-s", "--start", type=int, default=96)
    parser.add_argument("-e", "--end", type=int, default=100)
    parser.add_argument("-t", "--timeout", type=int, default=60)
    parser.add_argument("-r", "--runs", type=int, default=60)
    parser.add_argument('-c', '--crack', action='store_true', default=False)
    args = parser.parse_args()

    # Basic tests
    assert run_cmd(['./kry']) != 0
    assert run_cmd(['./kry', '-g', '-1']) != 0
    assert run_cmd(['./kry', '-g', '0']) != 0
    assert run_cmd(['./kry', '-g', '1']) != 0
    assert run_cmd(['./kry', '-g', '2']) != 0
    assert run_cmd(['./kry', '-g', '3']) != 0
    assert run_cmd(['./kry', '-g', '4']) != 0
    assert run_cmd(['./kry', '-g', '5']) != 0
    assert run_cmd(['./kry', '-g', '6']) != 0
    #assert run_cmd(['./kry', '-g', '7']) == 0
    assert run_cmd(['./kry', '-g', '32']) == 0
    assert run_cmd(['./kry', '-g', '33']) == 0
    assert run_cmd(['./kry', '-g', 'bla']) != 0
    assert run_cmd(['./kry', '-g', '32', '64']) != 0
    #assert run_cmd(['./kry', '-e', '1', '0x2', '3']) != 0
    #assert run_cmd(['./kry', '-d', '1', '2', '0x3']) != 0
    #assert run_cmd(['./kry', '-b', '0']) != 0
    #assert run_cmd(['./kry', '-b', '0x1', '2', '3']) != 0
    #assert run_cmd(['./kry', '-e', '0x7', '0x5', '0xc']) != 0
    #assert run_cmd(['./kry', '-e', '0xb', '0x0', '0x25']) != 0
    #assert run_cmd(['./kry', '-d', '0xb', '0x0', '0x25']) != 0
    #assert run_cmd(['./kry', '-b', '0xb', '0x0', '0x25']) != 0

    for i in range(args.runs):
        bitlen, keys = gen_keys(args.start, args.end, args.timeout)
        N = int(keys.n.decode("ascii"), 16)
        M = bytes(str(hex(random.randrange(1, N))), encoding="ascii")
        cipher = encrypt(keys.e, keys.n, M, args.timeout)
        print("Conf(M=%s,C=%s,bitlen=%d,p=%s,q=%s,n=%s,e=%s,d=%s)" % (M, cipher, bitlen, keys.p, keys.q, keys.n, keys.e, keys.d))
        assert keys.e != keys.d
        P = int(keys.p.decode("ascii"), 16)
        Q = int(keys.q.decode("ascii"), 16)
        assert P != Q
        # assert gmpy2.is_prime(P)
        # assert gmpy2.is_prime(Q)
        if bitlen & 1 == 0:
            assert P.bit_length() == bitlen / 2
            assert Q.bit_length() == bitlen / 2
        else:
            assert (P.bit_length() == (bitlen // 2) and Q.bit_length() == (bitlen // 2) + 1) or (P.bit_length() == (bitlen // 2) + 1 and Q.bit_length() == (bitlen // 2))
        assert N.bit_length() == bitlen
        assert N & 1 == 1
        msg = decrypt(keys.d, keys.n, cipher, args.timeout)
        assert msg == M
        if args.crack:
            start = time.time()
            broken = crack(keys.e, keys.n, cipher, args.timeout)
            end = time.time()
            print("Time to crack: ", end - start, " seconds")
            # print(broken.m)
            # print(M)
            # print(broken.p, broken.q, broken.d, broken.e)
            assert broken.m == M
            assert broken.p == keys.p or broken.p == keys.q
            assert broken.q == keys.q or broken.q == keys.p

if __name__== "__main__":
  main()