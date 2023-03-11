/**
 * KRY, projekt č.2: Implementace a prolomení RSA
 * Author: Katarína Grešová, xgreso00
 * Date 26.4.2020
 */

#include <iostream>
#include <string>
#include <cstddef>
#include <gmpxx.h>

using namespace std;

class RsaAlgorithm {

    public:
    virtual void execute() = 0;
    bool SolovayStrassen(mpz_class n, int iter);
    int JacobiSymbol(mpz_class a, mpz_class n);
    mpz_class GenerateRandomPrime(long bits);
    mpz_class gcd(mpz_class num1, mpz_class num2);
    mpz_class Inverse(mpz_class num, mpz_class mod);
    long TrivialDivision(mpz_class n, long to);
    mpz_class PollardsFactorization(mpz_class &number);
    mpz_class generateRandomNumber(mpz_class min, mpz_class max);
    mpz_class Factorize(mpz_class n);
};

class KeyGenerator: public RsaAlgorithm {

    public:
    explicit KeyGenerator(long b);

    private:
    long b;
    void execute() override;
};

class Encryptor: public RsaAlgorithm {

    public:
    Encryptor(mpz_class e, mpz_class n, mpz_class m);

    private:
    mpz_class e;
    mpz_class n;
    mpz_class m;
    void execute() override;

};

class Decryptor: public RsaAlgorithm {

    public:
    Decryptor(mpz_class d, mpz_class n, mpz_class c);

    private:
    mpz_class d;
    mpz_class n;
    mpz_class c;
    void execute() override;
};

class Breaker: public RsaAlgorithm {

    public:
    Breaker(mpz_class e, mpz_class n, mpz_class c);

    private:
    mpz_class e;
    mpz_class n;
    mpz_class c;
    void execute() override;
};

class Arguments {

    public:
    static RsaAlgorithm* parse(int argc, char **argv);
    static void printHelp();

    private:
    static RsaAlgorithm* parseGenerator(int argc, char **argv);
    static RsaAlgorithm* parseEncryptor(int argc, char **argv);
    static RsaAlgorithm* parseDecryptor(int argc, char **argv);
    static RsaAlgorithm* parseBreaker(int argc, char **argv);
};

const long PRIMES_TOP = 1000000;