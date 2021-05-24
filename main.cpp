#include <iostream>
#include <fstream>
#include <ctime>
#include <cmath>
#include <random>
#include "BigInt.hpp"
//какой длины должно быть число чтобы ключ был 128 бит
size_t KEY_BITS_LENGTH = 128;

size_t KEY_SIZE() {
    return (KEY_BITS_LENGTH * log10(2) + 1);
}

// base^exponent mod modulus
BigInt modular_pow(BigInt base, BigInt exponent, const BigInt &modulus) {
    BigInt result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    return result;
}

// lcm
BigInt lcm(const BigInt &a, const BigInt &b) {
    return abs(a * b);
}

// расширенный алгоритм евклида
std::vector<BigInt> extended_gcd(BigInt a, BigInt b) {
    BigInt x(0), old_x(1);
    BigInt y(1), old_y(0);

    while (b != 0) {
        auto quotient = a / b;
        BigInt temp_a = a;
        a = b;
        b = temp_a - quotient * b;

        BigInt temp_old_x = old_x;
        old_x = x;
        x = temp_old_x - quotient * x;

        BigInt temp_old_y = old_y;
        old_y = y;
        y = temp_old_y - quotient * y;
    }

    return {a, old_x, old_y};
}

std::random_device rd;
std::mt19937 generator(rd());
std::uniform_real_distribution<double> rnd_distrib(0.0, 1.0);

BigInt big_rand_range(int minNum, const BigInt &maxNum) {
    return (maxNum - minNum) * (int) (100 * rnd_distrib(generator)) / 100 + minNum;
}

std::vector<int> first_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                                 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                                 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
                                 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
                                 293, 307, 311, 313, 317, 331, 337, 347, 349};

BigInt simple_prime() {
    while (true) {
        auto prime_num = BigInt::big_random(KEY_SIZE());
        for (auto f_prime : first_primes) {
            if (prime_num % f_prime == 0 && f_prime * f_prime <= prime_num) {
                break;
            }

            return prime_num;
        }
    }
}

const size_t MILLER_RABIN_TRIALS_AMOUNT = 20;

// пробаблистический алгоритм миллера-рабина
bool miller_rabin_primality(const BigInt &mrc) {
    int max_divisions_by_two = 0;
    BigInt ec = mrc - 1;
    while (ec % 2 == 0) {
        ec /= 2;
        max_divisions_by_two += 1;
    }

    auto miller_trial = [ec, mrc, max_divisions_by_two](const BigInt &round_tester) {
        if (modular_pow(round_tester, ec, mrc) == 1) {
            return false;
        }

        for (BigInt i = 0; i < max_divisions_by_two; i++) {
            if (modular_pow(round_tester, pow(BigInt(2), i.to_int()) * ec, mrc) == mrc - 1) {
                return false;
            }
        }

        return true;
    };

    for (int i = 0; i < MILLER_RABIN_TRIALS_AMOUNT; i++) {
        auto round_tester = big_rand_range(2, mrc);
        if (miller_trial(round_tester)) {
            return false;
        }
    }

    return true;
}

BigInt get_random_prime() {
    while (true) {
        auto possible_prime = simple_prime();
        if (!miller_rabin_primality(possible_prime)) {
            continue;
        }

        return possible_prime;
    }
}

const BigInt BIGGEST_E = pow(BigInt(2), 16) + 2;

BigInt choose_e(const BigInt &lcmv) {
    while (true) {
        auto e = big_rand_range(3, BIGGEST_E);
        if (e < lcmv && gcd(e, lcmv) == 1) {
            return e;
        }
    }
}
//шифрование
std::vector<BigInt> encrypt(const std::string &message, const BigInt &exponent, const BigInt &modulus) {
    std::vector<BigInt> result;
    result.reserve(message.size());

    for (char c : message) {
        auto encrypted_char = modular_pow(c, exponent, modulus);
        result.push_back(encrypted_char);
    }

    return result;
}

std::string decrypt(const std::vector<BigInt> &encrypted, const BigInt &pkey, const BigInt &modulus) {
    std::string result;

    for (const auto &byte : encrypted) {
        auto decrypted_char = modular_pow(byte, pkey, modulus);
        result += char(decrypted_char.to_int());
    }

    return result;
}

std::vector<BigInt> generate_keys() {
    std::cout << "Генерируем P... ";
    auto P = get_random_prime();
    std::cout << P << "\n";
    std::cout << "Генерируем Q... ";
    auto Q = get_random_prime();
    std::cout << Q << "\n";

    std::cout << "Считаем ключи...\n";
    auto n = P * Q;
    auto lcm_v = lcm(P - 1, Q - 1);
    auto e = choose_e(lcm_v);

    auto ext_gcd_res = extended_gcd(e, lcm_v);  // gcd, x, y
    auto d = ext_gcd_res[1];
    if (ext_gcd_res[1] < 0) {
        d += lcm_v;
    }

    return {e, n, d};
}

void write_keys(const BigInt &e, const BigInt &n, const BigInt &d) {
    std::ofstream private_key("private.key", std::ios::out | std::ios::binary);
    std::ofstream public_key("public.key", std::ios::out | std::ios::binary);

    if (!private_key.is_open() || !public_key.is_open()) {
        throw std::runtime_error("Ошибка открытия файла вывода\n");
    }

    private_key << e << '\n' << n;
    public_key << d << '\n' << n;
}

std::vector<BigInt> read_keys() {
    std::ifstream private_key("private.key", std::ios::in | std::ios::binary);
    std::ifstream public_key("public.key", std::ios::in | std::ios::binary);

    if (!private_key.is_open()) {
        throw std::runtime_error("Файл с приватным ключём не найден\n");
    }

    if (!public_key.is_open()) {
        throw std::runtime_error("Файл с публичным ключём не найден\n");
    }

    BigInt e, n, d;

    private_key >> e >> n;
    public_key >> d;

    std::cout << "e: " << e << "\nn: " << n << "\nd: " << d << "\n";

    return {e, n, d};
}

void test_encryption_decryption(const BigInt &e, const BigInt &n, const BigInt &d) {
    std::string message;
    std::cout << "Введите текст:\n";
    std::cin.get();
    std::getline(std::cin, message);

    std::cout << "Шифруем...\n";
    auto encrypted_message = encrypt(message, e, n);
    auto decrypted_message = decrypt(encrypted_message, d, n);

    std::cout << "Оригинальное сообщение:  " << message << std::endl;
    std::cout << "Зашифрованное сообщение: ";
    for (const auto &enc : encrypted_message) std::cout << enc;
    std::cout << std::endl;
    std::cout << "Дешифрованное сообщение: " << decrypted_message << std::endl;
}

void set_key_length() {
    int new_key_length = -1;
    while (new_key_length <= 0) {
        std::cout << "Новый размер ключа\n"
                     ">>>";
        std::cin >> new_key_length;
    }

    KEY_BITS_LENGTH = new_key_length;
}

int main() {
    std::vector<BigInt> keys_data;

    while (true) {
        std::cout << "Меню\n"
                     "1. Сгенерировать ключи\n"
                     "2. Прочитать ключи с диска\n"
                     "3. Зашифровать/расшифровать текст\n"
                     "4. Установить размер ключа (" << KEY_BITS_LENGTH << "bits сейчас)\n"
                                                                          "------------------------------------------------------------------\n"
                                                                          "0. Выйти\n"
                                                                          ">>>";

        int item = 0;
        std::cin >> item;
        switch (item) {
            case 0:
                goto exit;
            case 1:
                keys_data = generate_keys();
                write_keys(keys_data[0], keys_data[1], keys_data[2]);
                break;
            case 2:
                keys_data = read_keys();
                break;
            case 3:
                test_encryption_decryption(keys_data[0], keys_data[1], keys_data[2]);
                break;
            case 4:
                set_key_length();
                break;
            default:
                continue;
        }
    }

    exit:
    return 0;
}
