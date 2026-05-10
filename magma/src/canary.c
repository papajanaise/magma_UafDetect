#ifdef __cplusplus
extern "C" {
#endif

#include "canary.h"
#include "common.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

static pstored_data_t data_ptr = NULL;

static struct sigaction prev_sigsegv, prev_sigabrt, prev_sigbus;

static void magma_crash_handler(int sig, siginfo_t *info, void *ctx)
{
    if (data_ptr) {
#ifdef MAGMA_HARDEN_CANARIES
        mprotect(data_ptr, FILESIZE, PROT_READ | PROT_WRITE);
#endif
        memcpy(data_ptr->consumer_buffer, data_ptr->producer_buffer, sizeof(data_t));
        __sync_synchronize();
        data_ptr->consumed = false;
    }

    /* Chain to the previous handler (e.g. ASAN) instead of SIG_DFL */
    struct sigaction *prev = (sig == SIGSEGV) ? &prev_sigsegv :
                             (sig == SIGABRT) ? &prev_sigabrt : &prev_sigbus;
    if (prev->sa_flags & SA_SIGINFO) {
        if (prev->sa_sigaction) prev->sa_sigaction(sig, info, ctx);
    } else {
        if (prev->sa_handler == SIG_DFL) {
            signal(sig, SIG_DFL);
            raise(sig);
        } else if (prev->sa_handler != SIG_IGN) {
            prev->sa_handler(sig);
        }
    }
}

static void magma_protect(int write)
{
    if (write == 0) {
        mprotect(data_ptr, FILESIZE, PROT_READ);
    } else {
        mprotect(data_ptr, FILESIZE, PROT_READ | PROT_WRITE);
    }
}

static bool magma_init(void)
{
    static bool init_called = false;
    if (init_called) {
        // if init is called more than once, then the first call failed, so
        // we assume every following call will fail.
        return false;
    }
    init_called = true;
    const char *file = getenv("MAGMA_STORAGE");
    if (file == NULL) {
        file = NAME;
    }
    int fd = open(file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Monitor not running. Canaries will be disabled.\n");
        data_ptr = NULL;
        return false;
    } else {
        data_ptr = mmap(0, FILESIZE, PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = magma_crash_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, &prev_sigsegv);
        sigaction(SIGABRT, &sa, &prev_sigabrt);
        sigaction(SIGBUS,  &sa, &prev_sigbus);

#ifdef MAGMA_HARDEN_CANARIES
        magma_protect(0);
#endif
        return true;
    }
}

void magma_log(const char *bug, int condition)
{
#ifndef MAGMA_DISABLE_CANARIES
    if (!data_ptr && !magma_init()) {
        return;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(1);
#endif

    pcanary_t prod_canary   = stor_get(data_ptr->producer_buffer, bug);
    prod_canary->reached   += 1;
    prod_canary->triggered += (bool)condition;
    if (data_ptr->consumed) {
        memcpy(data_ptr->consumer_buffer, data_ptr->producer_buffer, sizeof(data_t));
        // memory barrier
        __sync_synchronize();
        data_ptr->consumed = false;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(0);
#endif
#endif
    return;
}

void magma_free_log(const char *bug, int condition)
{
#ifndef MAGMA_DISABLE_CANARIES
    if (!data_ptr && !magma_init()) {
        return;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(1);
#endif

    pcanary_t prod_canary = stor_get(data_ptr->producer_buffer, bug);
    prod_canary->free_reached   += 1;
    prod_canary->free_triggered += (bool)condition;
    if (data_ptr->consumed) {
        memcpy(data_ptr->consumer_buffer, data_ptr->producer_buffer, sizeof(data_t));
        // memory barrier
        __sync_synchronize();
        data_ptr->consumed = false;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(0);
#endif
#endif
    return;
}

#ifdef __cplusplus
}
#endif