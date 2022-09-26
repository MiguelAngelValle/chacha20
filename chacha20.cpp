#include <iostream>
#include <iomanip>
#include <fstream>
#include <string> 
#include "sodium.h"

int main() {
    unsigned char buf[128];
    
    if (sodium_init() == -1) {
        return 1;
    }

    std::cout << sizeof(buf) << std::endl;
    std::cout << std::setfill('0') << std::setw(2);
    std::cout.setf(std::ios::hex, std::ios::basefield);

    unsigned char* plaintext = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    char* buffer = NULL;
    unsigned long long clen;
    unsigned char* plaintext2 = NULL;

    std::ifstream plaintextfile("test.txt", std::ifstream::binary);
    if (plaintextfile) {

        // get length of file:
        plaintextfile.seekg(0, plaintextfile.end);
        clen = plaintextfile.tellg();
        plaintextfile.seekg(0, plaintextfile.beg);

        buffer = new char[clen];
        ciphertext = new unsigned char[clen];
        plaintext2 = new unsigned char[clen];

        std::cout << "Reading " << clen << " characters... ";
        plaintextfile.read(buffer, clen);

        if (plaintextfile)
            std::cout << "all characters read successfully.";
        else
            std::cout << "error: only " << plaintextfile.gcount() << " could be read";
        plaintextfile.close();
        std::cout << std::endl;
    }
    std::cout << "---" << std::endl;
    plaintext = (unsigned char*)buffer;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;

    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(key, sizeof(key));

    int result = crypto_stream_chacha20_xor_ic(ciphertext, plaintext, clen, nonce, 0, key);
    int result2 = crypto_stream_chacha20_xor_ic(plaintext2, ciphertext, clen, nonce, 0, key);
    for (int i = 0; i < clen; i++)
        std::cout << (unsigned int)ciphertext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext2[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    std::cout << "Error Enc = " << result << std::endl;
    std::cout << "Error Dec = " << result2 << std::endl;

    delete[] plaintext2;
    delete[] ciphertext;
    delete[] buffer;
}
