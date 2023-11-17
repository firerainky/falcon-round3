
#include "api.h"
#include "inner.h"
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>


int randombytes(unsigned char *x, unsigned long long xlen);


int main() {
    static unsigned char       seed[48];
    randombytes(seed, 48);
    static unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

    struct timeval start_time, end_time;
    long long total_time = 0LL;
    crypto_sign_keypair(pk, sk);
    gettimeofday(&start_time, NULL); // Record the start time
    for (int i = 0;i<1000;++i) {
        crypto_sign_keypair(pk, sk);
    }
    gettimeofday(&end_time, NULL); // Record the end time
    long long elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL + (end_time.tv_usec - start_time.tv_usec);
    printf("Keygen: Elapsed Time: %lld µs\n", elapsed_time/1000);

    unsigned char       *m, *sm;
    unsigned long long  mlen, smlen;
    mlen = 32;
    m = (unsigned char *)calloc(mlen, sizeof(unsigned char));

    for (int i = 0;i<mlen; ++i) {
        m[i] = i;
    }
    m[mlen] = 0;

    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    crypto_sign(sm, &smlen, m, mlen, sk);

    gettimeofday(&start_time, NULL); // Record the start time
    for (int i = 0;i<1000;++i) {
        crypto_sign(sm, &smlen, m, mlen, sk);
    } 
    gettimeofday(&end_time, NULL); // Record the end time
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL + (end_time.tv_usec - start_time.tv_usec);
    printf("Sign: Elapsed Time: %lld µs\n", elapsed_time/1000);

    gettimeofday(&start_time, NULL); // Record the start time
    for (int i = 0;i<1000;++i) {
        crypto_sign(sm, &smlen, m, mlen, sk);
        crypto_sign_open(m, &mlen, sm, smlen, pk);
    }
    gettimeofday(&end_time, NULL); // Record the end time
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL + (end_time.tv_usec - start_time.tv_usec);
    printf("Verify: Elapsed Time: %lld µs\n", elapsed_time/1000);
}