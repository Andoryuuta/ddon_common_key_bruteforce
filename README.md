# ddon_common_key_bruteforce
Tool for bruteforcing the Camellia key used in the DDON Login Server <-> Client exchange. This works by seeding the PRNG by interating over each millisecond, generating a large depth of crypto key characters for that PRNG state, and then attempting to decrypt the provided ciphertext and checking against a know crib value (the `L2C_CLIENT_CHALLENGE_RES` packet header).

This has been optimized as much as I reasonably could (parallel processing, inlining, etc). However, profiling shows that ~90% of CPU time is spent within the NTT Camellia implement's keygen and block decrypt method. If speed ends up being an issue for some packet captures, we may need to move over to an optimized Camellia implementation that uses AES-NI & AVX. Such as implementation within the Linux kernel or libgcrypt.

## Usage
1. Take the third packet from a Login Server <-> Client exchange.
2. Remove the size prefix bytes (`0060`), then take the next 16 bytes.
3. Run `ddon_common_key_bruteforce [16 byte ciphertext as hex]`

```
> ddon_common_key_bruteforce fb3340b47214cc1e53e6d8e6652ef038

Starting bruteforcer with 8 threads. Progress will be reported periodically.
Progress: 0/86400000ms (0 work-seconds)
Progress: 8000/86400000ms (8 work-seconds)
Progress: 16000/86400000ms (16 work-seconds)
Progress: 24000/86400000ms (24 work-seconds)
Found match at ms26242, i:237, key: hREUMreQsowZisof2tBCtXrXUvcvqVUv
Found key, exiting.
```

## Help
```
Usage: ddon_common_key_bruteforce [options] payload

Positional arguments:
payload         The payload to be bruteforced against.
                This should be first 16 bytes of the second packet sent from the login server (do not include the 0060 prefix)

Optional arguments:
-h --help       shows help message and exits
-v --version    prints version information and exits
--start_second  Start of PRNG seed range (in seconds) [default: 0]
--end_second    End of PRNG seed range (in seconds) [default: 86400]
--key_depth     How many key chars are generated per millisecond that is bruteforced [default: 1024]
--thread_limit  Maximum amount of CPU threads used for bruteforcing
```


