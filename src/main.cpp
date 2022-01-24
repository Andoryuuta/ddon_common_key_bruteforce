#include <iostream>
#include <cstdint>
#include <thread>
#include <mutex>
#include <string>
#include <chrono>
#include "camellia.h"
#include "ctpl_stl.h"
#include "argparse.hpp"
#include "seeded_xorshift_128.hpp"

#ifdef DDON_SIMD_ENABLED
#include "simd_brute_force.h"
#endif

// Mutex for writing to stdout across multiple threads withotu conflict.
std::mutex stdout_mutex;

#define KEY_BIT_LENGTH 256
#define KEY_LENGTH 32
const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char* camellia_default_key = "f23e98HafJdSoaj80QBjhh23oajgklSa";
const char* camellia_default_iv = "$cbM6WP)aX=%J^zA";


//unsigned char ciphertext[] = { 0xF1, 0x36, 0xF3, 0x39, 0x20, 0x42, 0xF4, 0xCF, 0x3B, 0xF6, 0xB9, 0xCD, 0x6D, 0x79, 0xDF, 0x94 }; // stream61 -- Found match at ms4921, i:652, key: UpJlo7MYHVbxS3Xs7LAx-sptfA5Q3Mw-
//unsigned char ciphertext[] = { 0x3b, 0x44, 0x0b, 0x4e, 0x0e, 0x65, 0xf4, 0xd7, 0x33, 0x22, 0xe9, 0xf3, 0x7c, 0x0d, 0x73, 0xad }; // stream83 - no match
//unsigned char ciphertext[] = { 0xF6, 0xC0, 0x7B, 0x24, 0x58, 0x29, 0x11, 0x19, 0xC8, 0xF2, 0x87, 0xD6, 0x0F, 0x63, 0x92, 0x24 }; // rumi unk1 -- no match
//unsigned char ciphertext[] = { 0x67, 0x62, 0x71, 0x6E, 0xBD, 0x4E, 0x0D, 0x13, 0x23, 0x74, 0x38, 0xF0, 0x95, 0xC3, 0x33, 0xC7 }; // rumi unk2 - no match
//unsigned char ciphertext[] = { 0x8C, 0x66, 0x25, 0x1C, 0xE1, 0xC3, 0xF3, 0x89, 0x04, 0x2F, 0x18, 0x93, 0x0B, 0xD1, 0x36, 0x55 }; // rumi unk3 -- Found match at ms5151, i:400, key: c1Waaw4GyuUpEpV_-77bAJNQfKhqFNTU
//unsigned char ciphertext[] = { 0x73, 0x47, 0xB7, 0x36, 0x67, 0xC0, 0x5B, 0xE3, 0x1F, 0x2C, 0x05, 0xF5, 0x14, 0x4B, 0xDC, 0xA0 }; // rumi unk4 -- no match 
//unsigned char ciphertext[] = { 0xFB, 0x33, 0x40, 0xB4, 0x72, 0x14, 0xCC, 0x1E, 0x53, 0xE6, 0xD8, 0xE6, 0x65, 0x2E, 0xF0, 0x38 }; // rumi unk5 -- Found match at ms26242, i:237, key: hREUMreQsowZisof2tBCtXrXUvcvqVUv

unsigned char ciphertext[16] = { 0 };


inline bool bruteforce_millisecond(int ms, int key_depth) {
    SeededXorshift128 mrand;
    KEY_TABLE_TYPE keytable;
    unsigned char plaintext[16] = { 0 };
    std::vector<char> key_buffer(key_depth);

    // Initialize PRNG with the current ms time, then generate the full potential key buffer.
    mrand.Init(ms);
    for (size_t i = 0; i < key_buffer.size(); i++)
    {
        key_buffer[i] = alphabet[mrand.NextRand() & 63];
    }

    // Go over the key buffer and try every index as as the starting position of the key.
    for (size_t i = 0; i < key_buffer.size()-KEY_LENGTH; i++)
    {

        Camellia_Ekeygen(KEY_BIT_LENGTH, (unsigned char*)(key_buffer.data()+i), keytable);
        Camellia_DecryptBlock(KEY_BIT_LENGTH, ciphertext, keytable, plaintext);

        // XOR output with the provided IV.
        for (int j = 0; j < CAMELLIA_BLOCK_SIZE; j++) {
            plaintext[j] ^= camellia_default_iv[j];
        }

        // Check if the current key index decrypts to the expected LoginServer->Client packet.
        if (
                plaintext[0] == 0x01 && // Group IDX
                plaintext[1] == 0x00 && // Handler ID lo
                plaintext[2] == 0x00 && // Handler ID hi
                plaintext[3] == 0x02 && // Handler sub id
                plaintext[4] == 0x34 && // Unk field, 0x34 when comes from server? unverified

                // Packet counter bytes. Always seems to be 0 when coming from the server, which this packet is.
                // This needs to be verified.
                plaintext[5] == 0x00 &&
                plaintext[6] == 0x00 &&
                plaintext[7] == 0x00 &&
                plaintext[8] == 0x00
            ) {
                const std::lock_guard<std::mutex> lock(stdout_mutex);
                char key_copy[KEY_LENGTH + 1] = { 0 };
                std::memcpy(key_copy, key_buffer.data() + i, KEY_LENGTH);
                std::cout << "Found match at ms" << ms << ", i:" << i << ", key: " << key_copy << "\n";
                return true;
        }
    }

    return false;
}

 int bruteforce(int start_time_seconds, int end_time_seconds, int key_depth, int num_threads) {

    std::cout << "Starting bruteforcer with " << num_threads << " threads. Progress will be reported periodically.\n";

    // Create a thread pool with all logical processors to perform the bruteforce in parallel.
    ctpl::thread_pool pool(num_threads);

    // Bruteforce every millisecond from start_time_seconds -> end_time_seconds.
    for (auto i = start_time_seconds * 1000; i < end_time_seconds * 1000; i += num_threads) {
        std::vector<std::future<bool>> results(num_threads);

        // Queue all tasks on different threads.
        for (int thread_idx = 0; thread_idx < num_threads; thread_idx++) {
            results[thread_idx] = pool.push([thread_idx, i, key_depth](int id) {
                return bruteforce_millisecond(i + thread_idx, key_depth);
            });
        }

        // Await all tasks.
        for (int thread_idx = 0; thread_idx < num_threads; thread_idx++) {
            bool found_key = results[thread_idx].get();


            if (found_key) {
                const std::lock_guard<std::mutex> lock(stdout_mutex);
                std::cout << "Found key, exiting." << "\n";
                return 0;
            }
        }

        // Log every 1,000 batches.
        if (i % (num_threads * 1000) == 0) {
            const std::lock_guard<std::mutex> lock(stdout_mutex);
            std::cout << "Progress: " << i << "/" << end_time_seconds * 1000 << "ms (" << i/1000 << " work-seconds)" << "\n";
        }
    }


    const std::lock_guard<std::mutex> lock(stdout_mutex);
    std::cout << "Failed to find key within the given parameters\n";
    return -1;
}

int main(int argc, char** argv) {
    argparse::ArgumentParser program("ddon_common_key_bruteforce");

    program.add_argument("--start_second")
        .scan<'i', int>()
        .default_value(0)
        .required()
        .help("Start of PRNG seed range (in seconds)");

    program.add_argument("--end_second")
        .scan<'i', int>()
        .default_value(24 * 60 * 60) // Default is all the seconds within 24-hours.
        .required()
        .help("End of PRNG seed range (in seconds)");

    program.add_argument("--key_depth")
        .scan<'i', int>()
        .default_value(1024)
        .required()
        .help("How many key chars are generated per millisecond that is bruteforced");

    program.add_argument("--thread_limit")
        .scan<'i', int>()
        .help("Maximum amount of CPU threads used for bruteforcing");

    program.add_argument("payload")
        .help("The payload to be bruteforced against.\n\t\tThis should be first 16 bytes of the second packet sent from the login server (do not include the 0060 prefix)");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << "\n";
        std::cerr << program;
        std::exit(1);
    }

    // Load our input parameters
    int start_time_seconds = program.get<int>("--start_second");
    int end_time_seconds = program.get<int>("--end_second");
    int key_depth = program.get<int>("--key_depth");

    int num_threads = std::thread::hardware_concurrency();
    if (auto fn = program.present<int>("--thread_limit")) {
        num_threads = *fn;
    }

    if (program.get<std::string>("payload").length() == 16 * 2) {
        // Convert hex string to std::vector<uint8_t>;
        auto payload_str = program.get<std::string>("payload");
        std::vector<uint8_t> payload;
         for (size_t i = 0; i < payload_str.length(); i += 2)
        {
            std::istringstream ss(payload_str.substr(i, 2));
            uint32_t x;
            ss >> std::hex >> x;
            payload.push_back((uint8_t)x);
        }

        std::memcpy(ciphertext, payload.data(), sizeof(ciphertext));
    }
    else
    {
        std::cerr << "Payload must be exactly 16 hex digits!\n";
        std::cerr << program;
        std::exit(1);
    }

#ifdef DDON_SIMD_ENABLED
    SimdBruteForce *sbf = new SimdBruteForce(num_threads);
    sbf->brute_force(start_time_seconds, ciphertext, true);
    return 0;
#endif

    bruteforce(start_time_seconds, end_time_seconds, key_depth, num_threads);
	return 0;
}