#ifdef DDON_SIMD_ENABLED

#ifndef DDON_SIMD_BRUTE_FORCE_H
#define DDON_SIMD_BRUTE_FORCE_H


#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <chrono>

#include "camellia_simd.h"

class SimdBruteForce {

private:
    const int KEY_LENGTH = 32;
    const int BLOCK_SIZE = 16;
    const unsigned char EXPECTED_LOGIN[5] = {0x01, 0x00, 0x00, 0x02, 0x34};
    const unsigned char EXPECTED_GAME[5] = {0x2C, 0x00, 0x00, 0x02, 0x34};
    const unsigned char KEY_SOURCE[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const unsigned char IV[16] = {0x24, 0x63, 0x62, 0x4D, 0x36, 0x57, 0x50, 0x29, 0x61, 0x58, 0x3D, 0x25, 0x4A, 0x5E,
                                  0x7A, 0x41};

    std::vector<std::thread *> threads;
    int num_threads;
    int ms;
    const unsigned char *crack_bytes;
    const unsigned char *expected_bytes;
    std::atomic_flag running;

    void thread_unlimited_depth(int offset) {

        unsigned char *decrypted_bytes = new unsigned char[KEY_LENGTH];
        unsigned char *key_buffer = new unsigned char[KEY_LENGTH];

        SeededXorshift128 rand;
        rand.Init(ms);

        for (int i = 0; i < offset; i++) {
            rand.NextRand();
        }

        while (running.test()) {
            for (size_t i = 0; i < KEY_LENGTH; i++) {
                key_buffer[i] = KEY_SOURCE[rand.NextRand() & 0x3F];
            }
            for (int i = 0; i < num_threads; i++) {
                rand.NextRand();
            }
            struct camellia_simd_ctx ctx_simd{};
            camellia_keysetup_simd128(&ctx_simd, key_buffer, KEY_LENGTH);
            camellia_decrypt_16blks_simd128(&ctx_simd, decrypted_bytes, crack_bytes);
            for (int i = 0; i < BLOCK_SIZE; i++) {
                decrypted_bytes[i] ^= IV[i];
            }
            if (decrypted_bytes[0] == expected_bytes[0] &&
                decrypted_bytes[1] == expected_bytes[1] &&
                decrypted_bytes[2] == expected_bytes[2] &&
                decrypted_bytes[3] == expected_bytes[3] &&
                decrypted_bytes[4] == expected_bytes[4]) {
                running.clear();
                // found it
            }
        }
    }

public:
    explicit SimdBruteForce(int p_num_threads) {
        num_threads = p_num_threads;
        num_threads = 1;
        threads = std::vector<std::thread *>();
        running.clear();
    }

    void brute_force(int p_ms, const unsigned char *p_crack_bytes, bool p_is_login) {
        if (running.test()) {
            return;
        }
        threads.clear();
        running.test_and_set();

        ms = p_ms;
        crack_bytes = p_crack_bytes;
        expected_bytes = p_is_login ? EXPECTED_LOGIN : EXPECTED_GAME;

        for (int i = 0; i < num_threads; i++) {
            std::thread *thread = new std::thread(&SimdBruteForce::thread_unlimited_depth, this, i);
            threads.push_back(thread);
        }

        for (int i = 0; i < num_threads; i++) {
            threads[i]->join();
        }
    }
};


#endif //DDON_SIMD_BRUTE_FORCE_H
#endif /* DDON_SIMD_ENABLED */