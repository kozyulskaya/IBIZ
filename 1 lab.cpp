#include <iostream>
#include <string>

std::string crypt(const std::string& text) {
    std::string cyphertext;

    for (char c : text) {
        cyphertext += char(24 - (c - 'a') + 1) + 'a';
    }

    return cyphertext;
}

int main() {
    std::string text;
    std::getline(std::cin, text);
    std::string crypted = crypt(text);
    std::cout << "Crypted text:       " << crypted << std::endl;
    std::cout << "Twice crypted text: " << crypt(crypted) << std::endl;
    return 0;
}