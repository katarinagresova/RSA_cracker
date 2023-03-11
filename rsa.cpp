/**
 * KRY, projekt č.2: Implementace a prolomení RSA
 * Author: Katarína Grešová, xgreso00
 * Date 26.4.2020
 */

#include "rsa.h"

using namespace std;

// global variable for generating random numbers
gmp_randclass rnd (gmp_randinit_default);

int main(int argc, char** argv) {
    try {
        RsaAlgorithm* algorithm = Arguments::parse(argc, argv);
        rnd.seed(time(NULL));
        algorithm->execute();
    } catch (invalid_argument& e) {
        cerr << e.what() << endl;
        Arguments::printHelp();
        return -1;
    }
}

/**
 * Generates keys of given length
 */
void KeyGenerator::execute() {

    mpz_class p, q, n, phi, e, d;

    long half;
    if (b % 2 == 0) {
        half = b / 2;
    } else {
        half = b / 2 + 1;
    }

    e = b > 2048 ? 65537 : 3;

    do {
        p = GenerateRandomPrime(half);
        q = GenerateRandomPrime(b - half);

        phi = (p - 1) * (q - 1);

    } while (gcd(e, phi) != 1);

    n = p * q;
    d = Inverse(e, phi);

    cout << hex << showbase << p << " " << q << " " << n << " " << e << " " << d << endl;
}

/**
 * Encrypts message using public key
 */
void Encryptor::execute() {
    mpz_class cipher;
    mpz_powm(cipher.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    cout << hex << showbase << cipher << endl;
}

/**
 * Decrypts message using private key
 */
void Decryptor::execute() {
    mpz_class decipher;
    mpz_powm(decipher.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
    cout << hex << showbase << decipher << endl;
}

/**
 * Breaks RSA encrypted message
 */
void Breaker::execute() {
    mpz_class p = Factorize(n);
    mpz_class q = n / p;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class d = Inverse(e, phi);

    mpz_class decipher;
    mpz_powm(decipher.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

    cout << hex << showbase << p << " " << q << " " << decipher << endl;
}

/**
 * Factorizes given number. First, trivial division is tried and then Pollard's Rho Algorithm.
 * @param n number to factorize
 * @return factor of n.
 */
mpz_class RsaAlgorithm::Factorize(mpz_class n) {
    mpz_class res = TrivialDivision(n, PRIMES_TOP);
    if(!res) {
        res = PollardsFactorization(n);
    }
    return res;
}

/**
 * Pollard's Rho Algorithm for Prime Factorization.
 * Implemented using source https://www.geeksforgeeks.org/pollards-rho-algorithm-prime-factorization/
 * @param number number to factorize
 * @return prime divisor of given number
 */
mpz_class RsaAlgorithm::PollardsFactorization(mpz_class &number) {
    mpz_class divisor = 1, target = number, x = 0, y = 0, c = 0;

    // no prime divisor for 1
    if (target == 1)
        return target;

    // even number means one of the divisors is 2
    if (target % 2 == 0)
        return mpz_class(2);

    do {

        // we will pick from the range [2, target]
        x = generateRandomNumber(2, target);
        y = x;

        // the constant in f(x)
        c = generateRandomNumber(1, target);

        // until the prime factor isn't obtained.
        // If n is prime, return n
        while (divisor == 1) {

            // Tortoise Move: x(i+1) = f(x(i))
            mpz_powm_ui(x.get_mpz_t(), x.get_mpz_t(), 2, target.get_mpz_t());
            x = (x + c + target) % target;

            // Hare Move: y(i+1) = f(f(y(i)))
            mpz_powm_ui(y.get_mpz_t(), y.get_mpz_t(), 2, target.get_mpz_t());
            y = (y + c + target) % target;
            mpz_powm_ui(y.get_mpz_t(), y.get_mpz_t(), 2, target.get_mpz_t());
            y = (y + c + target) % target;

            // calculate GDC of |x-y| and n
            divisor = gcd(abs(x - y), target);
        }

    } while (divisor == target);

    return divisor;
}

/**
 * Generates random number in range [min, max]
 * @param min lower bond of range
 * @param max upper bond of range
 * @return random number
 */
mpz_class RsaAlgorithm::generateRandomNumber(mpz_class min, mpz_class max) {
    return min + rnd.get_z_range((max - min) + 1);
}

/**
 * Solovay-Strassen method for testing prime numbers
 * @param n number for testing
 * @param iter number of iterations
 * @return True, if number most probably is a prime, False if number definitely is not a prime
 */
bool RsaAlgorithm::SolovayStrassen(mpz_class n, int iter) {
    mpz_class res, exp;
    mpz_class jacobi = 0;

    for (int i = 0; i < iter; i++) {
        mpz_class a = generateRandomNumber(2, n - 1);
        jacobi = JacobiSymbol(a, n);
        if (jacobi == 0) {
            return false;
        }
        exp = (n - 1) / 2;
        mpz_powm(res.get_mpz_t(), a.get_mpz_t(), exp.get_mpz_t(), n.get_mpz_t());
        if (jacobi == -1) {
            jacobi += n;
        }
        if (res != jacobi) {
            return false;
        }
    }

    return true;
}

/**
 * Computes Jacobi symbol (a/n)
 * @param a first operand
 * @param n second operand
 * @return Jacobi symbol
 */
int RsaAlgorithm::JacobiSymbol(mpz_class a, mpz_class n) {
    int ret = 1;
    mpz_class tmp;
    while (a != 0) {
        while (a % 2 == 0) {
            a = a/2;
            if (n % 8 == 3 || n % 8 == 5) {
                ret = -1 * ret;
            }
        }
        tmp = a;
        a = n;
        n = tmp;
        if (a % 4 == 3 && n % 4 == 3) {
            ret = -1 * ret;
        }
        a = a % n;
    }
    if (n == 1) {
        return ret;
    }
    return 0;
}

/**
 * Generates random prime of given bit length
 * @param bits minimal bit length
 * @return prime number
 */
mpz_class RsaAlgorithm::GenerateRandomPrime(long bits) {
    mpz_class randInt = rnd.get_z_bits(bits);
    mpz_setbit(randInt.get_mpz_t(), bits - 1);
    mpz_setbit(randInt.get_mpz_t(), bits - 2);
    mpz_setbit(randInt.get_mpz_t(), 0);

    while (!this->SolovayStrassen(randInt, 100)) {
        randInt += 2;
    }

    return randInt;
}

/**
 * Euclid algorithm for computing GCD
 * @param num1
 * @param num2
 * @return GCD of given numbers
 */
mpz_class RsaAlgorithm::gcd(mpz_class num1, mpz_class num2) {
    mpz_class x = num1, y = num2;
    mpz_class gcd;

    while (y != 0) {
        gcd = y;
        y = x % y;
        x = gcd;
    }

    return gcd;
}

/**
 * Compute inverse number using Euclid algorithm.
 * @param num number to find inverse of
 * @param mod modulus
 * @return inverse number
 */
mpz_class RsaAlgorithm::Inverse(mpz_class num, mpz_class mod) {
    mpz_class a = num, m = mod;
    mpz_class y = 0, x = 1;

    if (m == 1) {
        return 0;
    }

    while (a > 1) {
        mpz_class q = a / m;
        mpz_class t = m;

        m = a % m;
        a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0) {
        x += mod;
    }

    return x;
}

/**
 * Trivial division using Sieve of Eratosthenes
 * @param n number to factorize
 * @param to upper bound
 * @return factor
 */
long RsaAlgorithm::TrivialDivision(mpz_class n, long to) {
    bool * sieve = new bool[to];
    for (long i = 0; i < to; i++) {
        sieve[i] = true;
    }

    for (long i = 2; i < to; i++) {
        if (sieve[i]) {
            if (n % i == 0) {
                return i;
            }
            for (long j = i*2; j < to; j = j + i) {
                sieve[j] = false;
            }
        }
    }

    return 0;
}

RsaAlgorithm* Arguments::parse(int argc, char** argv) {

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        throw invalid_argument("Printing help message.");
    }

    if (argc < 3 || argc > 5) {
        throw invalid_argument("Invalid number of arguments.");
    }

    if (strcmp(argv[1], "-g") == 0) {
        return parseGenerator(argc, argv);
    } else if (strcmp(argv[1], "-e") == 0) {
        return parseEncryptor(argc, argv);
    } else if (strcmp(argv[1], "-d") == 0) {
        return parseDecryptor(argc, argv);
    } else if (strcmp(argv[1], "-b") == 0) {
        return parseBreaker(argc, argv);
    } else {
        throw invalid_argument("Unknown argument " + string(argv[1]));
    }
}

RsaAlgorithm* Arguments::parseGenerator(int argc, char** argv) {

    if (argc != 3) {
        throw invalid_argument("Invalid number of arguments for option -g.");
    }

    string arg = argv[2];
    size_t pos;
    long b = stol(arg, &pos);
    if (pos < arg.size()) {
        throw invalid_argument(arg);
    }

    if (b < 8) {
        throw invalid_argument("Minimal length of public modulus for this project is 8b.");
    }
    return new KeyGenerator(b);
}

KeyGenerator::KeyGenerator(long b) {
    this->b = b;
}

RsaAlgorithm* Arguments::parseEncryptor(int argc, char **argv){

    if (argc != 5) {
        throw invalid_argument("Invalid number of arguments for option -e.");
    }

    string arg_e = argv[2];
    string arg_n = argv[3];
    string arg_m = argv[4];

    mpz_class e = mpz_class(arg_e);
    mpz_class n = mpz_class(arg_n);
    mpz_class m = mpz_class(arg_m);

    return new Encryptor(e, n, m);
}

Encryptor::Encryptor(mpz_class e, mpz_class n, mpz_class m) {
    this->e = e;
    this->n = n;
    this->m = m;
}

RsaAlgorithm* Arguments::parseDecryptor(int argc, char **argv){
    if (argc != 5) {
        throw invalid_argument("Invalid number of arguments for option -d.");
    }

    string arg_d = argv[2];
    string arg_n = argv[3];
    string arg_c = argv[4];

    mpz_class d = mpz_class(arg_d);
    mpz_class n = mpz_class(arg_n);
    mpz_class c = mpz_class(arg_c);

    return new Decryptor(d, n, c);
}

Decryptor::Decryptor(mpz_class d, mpz_class n, mpz_class c) {
    this->d = d;
    this->n = n;
    this->c = c;
}

RsaAlgorithm* Arguments::parseBreaker(int argc, char **argv){
    if (argc != 5) {
        throw invalid_argument("Invalid number of arguments for option -b.");
    }

    string arg_e = argv[2];
    string arg_n = argv[3];
    string arg_c = argv[4];

    mpz_class e = mpz_class(arg_e);
    mpz_class n = mpz_class(arg_n);
    mpz_class c = mpz_class(arg_c);

    return new Breaker(e, n, c);
}

Breaker::Breaker(mpz_class e, mpz_class n, mpz_class c) {
    this->e = e;
    this->n = n;
    this->c = c;
}

void Arguments::printHelp() {
    cout << "Usage:" << endl;
    cout << "Generovani klicu:" << endl;
    cout << "  vstup: ./kry -g B" << endl;
    cout << "  vystup: P Q N E D" << endl;
    cout << "Sifrovani:" << endl;
    cout << "  vstup: ./kry -e E N M" << endl;
    cout << "  vystup: C" << endl;
    cout << "Desifrovani:" << endl;
    cout << "  vstup: ./kry -d D N C" << endl;
    cout << "  vystup: M" << endl;
    cout << "Prolomeni RSA:" << endl;
    cout << "  vstup: ./kry -b E N C" << endl;
    cout << "  vystup: P Q M" << endl;
    cout << "B ... pozadovana velikost verejneho modulu v bitech (napr. 1024)" << endl;
    cout << "P ... prvociclo (pri generovani nahodne)" << endl;
    cout << "Q ... jine prvocislo (pri generovani nahodne)" << endl;
    cout << "N ... verejny modulus" << endl;
    cout << "E ... verejny exponent (vetsinou 3)" << endl;
    cout << "D ... soukromy exponent" << endl;
    cout << "M ... otevrena zprava (cislo)" << endl;
    cout << "C ... zasifrovana zprava (cislo)" << endl;
    cout << "Vsechna cisla na vstupu i vystupu (krome B) jsou hexadecimalni a zacinaji 0x" << endl;
}