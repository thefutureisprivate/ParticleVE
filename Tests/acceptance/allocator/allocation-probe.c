/* Bounded allocation workload for the disposable native allocator comparison. */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void *worker(void *argument) {
        const unsigned char pattern = (unsigned char) (uintptr_t) argument;
        for (unsigned iteration = 0; iteration < 64; ++iteration) {
                unsigned char *slots[256];
                size_t lengths[256];
                for (unsigned i = 0; i < 256; ++i) {
                        lengths[i] = 16 + ((i * 31 + iteration * 17) % 4096);
                        slots[i] = calloc(1, lengths[i]);
                        assert(slots[i] != NULL);
                        for (size_t j = 0; j < lengths[i]; ++j)
                                assert(slots[i][j] == 0);
                        memset(slots[i], pattern, lengths[i]);
                }
                for (unsigned i = 0; i < 256; ++i) {
                        unsigned char *resized = realloc(slots[i], lengths[i] * 2 + 3);
                        assert(resized != NULL);
                        for (size_t j = 0; j < lengths[i]; ++j)
                                assert(resized[j] == pattern);
                        memset(resized + lengths[i], pattern, lengths[i] + 3);
                        free(resized);
                }
        }
        return NULL;
}

static uint64_t monotonic_ns(void) {
        struct timespec time;
        assert(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
        return (uint64_t) time.tv_sec * 1000000000 + (uint64_t) time.tv_nsec;
}

static unsigned long peak_rss_kib(void) {
        /* ru_maxrss can retain the fork/exec launcher's peak. VmHWM belongs
         * to this executable's current mm and excludes that earlier history.
         */
        int descriptor = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
        assert(descriptor >= 0);
        char status[8192];
        ssize_t size = read(descriptor, status, sizeof(status) - 1);
        assert(size > 0 && (size_t) size < sizeof(status) - 1);
        assert(close(descriptor) == 0);
        status[size] = '\0';
        char *field = strstr(status, "\nVmHWM:");
        assert(field != NULL);
        unsigned long peak;
        assert(sscanf(field, "\nVmHWM: %lu kB", &peak) == 1);
        return peak;
}

int main(int argc, char **argv) {
        setbuf(stdout, NULL);
        Dl_info owner;
        assert(dladdr(dlsym(RTLD_DEFAULT, "malloc"), &owner) != 0);
        printf("{\"pid\":%ld,\"malloc_owner\":\"%s\"}\n", (long) getpid(), owner.dli_fname);
        if (argc == 2) {
                assert(strcmp(argv[1], "--pressure-ok") == 0 || strcmp(argv[1], "--pressure-oom") == 0);
                const unsigned blocks = strcmp(argv[1], "--pressure-ok") == 0 ? 20 : 40;
                void *allocations[40];
                for (unsigned i = 0; i < blocks; ++i) {
                        allocations[i] = malloc(4 * 1024 * 1024);
                        assert(allocations[i] != NULL);
                        volatile unsigned char *pages = allocations[i];
                        for (unsigned offset = 0; offset < 4 * 1024 * 1024; offset += 4096)
                                pages[offset] = (unsigned char) i;
                }
                assert(usleep(100000) == 0);
                for (unsigned i = 0; i < blocks; ++i)
                        free(allocations[i]);
                printf("{\"touched_mib\":%u}\n", blocks * 4);
                return 0;
        }
        assert(argc == 1);
        assert(getchar() == '\n');
        uint64_t start = monotonic_ns();
        pthread_t threads[4];
        for (uintptr_t i = 0; i < 4; ++i)
                assert(pthread_create(&threads[i], NULL, worker, (void *) (i + 1)) == 0);
        for (unsigned i = 0; i < 4; ++i)
                assert(pthread_join(threads[i], NULL) == 0);
        for (unsigned i = 0; i < 16; ++i) {
                void *memory = NULL;
                assert(posix_memalign(&memory, 4096, 1024 * 1024 + i) == 0);
                assert(((uintptr_t) memory % 4096) == 0);
                memset(memory, 0x5a, 1024 * 1024 + i);
                free(memory);
        }
        uint64_t elapsed = monotonic_ns() - start;
        printf("{\"elapsed_ns\":%llu,\"max_rss_kib\":%lu,\"calloc_realloc_pairs\":65536,"
               "\"threads\":4,\"aligned_large_allocations\":16}\n",
               (unsigned long long) elapsed, peak_rss_kib());
        return 0;
}
