/* SPDX-License-Identifier: MIT
 *
 * fuzz_input - throws hostile bytes at everything the PAM module parses.
 *
 * The module is #included so that its static functions can be called directly.
 * Build it with the sanitizers (tests/pam/test_robustness.py does):
 *
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
 *       -I build/pam tests/pam/fuzz_input.c -o fuzz_input -lpam -lpthread -ldl
 *   ./fuzz_input [ITERATIONS [SEED]]
 *
 * A crash, an out-of-bounds access, a signed overflow or a failed invariant
 * ends the run with a non-zero status: the module runs inside sudo, login and
 * the screen locker, where a crash cannot be turned into "ignore".
 */
#include "../../pam/pam_facial_auth.c"

#include <assert.h>
#include <math.h>
#include <stdint.h>

static uint64_t rng = 0x9E3779B97F4A7C15ULL;

static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static unsigned pick(unsigned n)
{
    return (unsigned)(rnd() % n);
}

static const char *const TOKENS[] = {
    "ACCEPT", "SKIP", "STATE", "OK", "FAIL", "VERIFY", "accept", " ", "  ", "\t", "\r", "=", "==", "mode=",
    "timeout=", "score=", "reason=", "parallel", "parallel-tty", "sequential", "bogus", "nan", "NaN",
    "inf", "-inf", "-1", "0", "1e999", "1e-999", "0x1p3", "99999999999999999999", "%", "%00", "%zz",
    "\xff", "\xc3\x28", "A", "..", "/", "mode=parallel-tty", "timeout=2", "timeout=nan", "score=0.99",
};
#define N_TOKENS (sizeof TOKENS / sizeof TOKENS[0])

/* A line made of protocol-looking tokens mixed with raw bytes; never longer than cap-1. */
static size_t gen_line(char *out, size_t cap)
{
    size_t n = 0, target = pick((unsigned)cap);

    while (n < target) {
        if (pick(4) == 0) {
            out[n++] = (char)rnd();                       /* any byte, NUL and newlines included */
        } else {
            const char *t = TOKENS[pick(N_TOKENS)];
            size_t l = strlen(t);

            if (n + l >= cap)
                break;
            memcpy(out + n, t, l);
            n += l;
        }
    }
    out[n] = '\0';
    return n;
}

static void fuzz_parse_reply(unsigned long iterations)
{
    for (unsigned long i = 0; i < iterations; i++) {
        char line[MAX_LINE];
        struct reply r;

        gen_line(line, sizeof line);
        parse_reply(line, &r);
        assert(r.kind >= REPLY_NONE && r.kind <= REPLY_UNKNOWN);
        assert(strnlen(r.mode, sizeof r.mode) < sizeof r.mode);
        assert(strnlen(r.reason, sizeof r.reason) < sizeof r.reason);
        double t = sane_timeout(r.timeout);
        assert(t >= 0.5 && t <= 60.0);                    /* whatever the daemon announced */
    }
}

static void fuzz_sane_timeout(void)
{
    const double evil[] = { NAN, -NAN, INFINITY, -INFINITY, 0.0, -0.0, -1.0, 0.49999, 0.5, 60.0, 60.0001,
                            1e308, -1e308, 4.9e-324, 1e-320 };

    for (size_t i = 0; i < sizeof evil / sizeof evil[0]; i++) {
        double t = sane_timeout(evil[i]);
        assert(t >= 0.5 && t <= 60.0);
    }
    for (int i = 0; i < 100000; i++) {
        double d;
        uint64_t bits = rnd();

        memcpy(&d, &bits, sizeof d);                      /* every kind of double, NaN payloads too */
        double t = sane_timeout(d);
        assert(t >= 0.5 && t <= 60.0);
    }
}

static void fuzz_reader(unsigned long iterations)
{
    int sv[2];
    struct reader rd;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) {
        perror("socketpair");
        exit(2);
    }
    memset(&rd, 0, sizeof rd);
    rd.fd = sv[0];
    for (unsigned long i = 0; i < iterations; i++) {
        char chunk[3000], line[MAX_LINE];
        size_t n = pick(sizeof chunk);
        int rc;

        for (size_t k = 0; k < n; k++)
            chunk[k] = pick(8) == 0 ? '\n' : (char)rnd();
        if (write(sv[1], chunk, n) < 0 && errno != EAGAIN)
            perror("write");
        rc = reader_fill(&rd);
        assert(rd.len <= sizeof rd.buf);
        while (reader_pop(&rd, line, sizeof line)) {
            assert(strnlen(line, sizeof line) < sizeof line);
            assert(!memchr(line, '\n', strnlen(line, sizeof line)));
            assert(rd.len <= sizeof rd.buf);
        }
        if (rc != 0)
            rd.len = 0;                                   /* the module gives up on this connection */
    }
    close(sv[0]);
    close(sv[1]);
}

static void fuzz_pct_encode(unsigned long iterations)
{
    for (unsigned long i = 0; i < iterations; i++) {
        char in[300];
        size_t n = pick(sizeof in - 1);
        char *out;

        for (size_t k = 0; k < n; k++)
            in[k] = (char)(1 + pick(255));                /* no NUL inside a C string */
        in[n] = '\0';
        out = pct_encode(in);
        assert(out);
        assert(strlen(out) <= n * 3);
        for (const char *p = out; *p; p++) {
            if (*p == '%') {
                assert(isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2]));
                assert(!islower((unsigned char)p[1]) && !islower((unsigned char)p[2]));
                p += 2;
            } else {
                assert(isalnum((unsigned char)*p) || strchr("-._~", *p));
            }
        }
        free(out);
    }
    char *none = pct_encode(NULL);
    assert(none && !*none);
    free(none);
}

static void fuzz_parse_args(unsigned long iterations)
{
    static const char *const TEMPLATES[] = {
        "debug", "quiet", "allow_locked", "socket=/run/x.sock", "marker_dir=-", "marker_dir=/tmp/m",
        "mode=sequential", "mode=parallel", "mode=parallel-tty", "mode=zzz", "max_rescans=", "connect_timeout=",
    };

    for (unsigned long i = 0; i < iterations; i++) {
        char storage[8][64];
        const char *argv[8];
        int argc = (int)pick(9);
        struct options o;

        for (int k = 0; k < argc; k++) {
            const char *t = TEMPLATES[pick(sizeof TEMPLATES / sizeof TEMPLATES[0])];

            snprintf(storage[k], sizeof storage[k], "%s", t);
            if (t[strlen(t) - 1] == '=' && !strncmp(t, "max_", 4))
                snprintf(storage[k] + strlen(t), sizeof storage[k] - strlen(t), "%d", (int)rnd());
            else if (t[strlen(t) - 1] == '=')
                snprintf(storage[k] + strlen(t), sizeof storage[k] - strlen(t), "%s",
                         TOKENS[pick(N_TOKENS)]);
            else if (pick(10) == 0)
                gen_line(storage[k], sizeof storage[k]);
            argv[k] = storage[k];
        }
        parse_args(NULL, argc, argv, &o);                 /* NULL pamh: pam_syslog tolerates it */
        assert(o.max_rescans >= 0 && o.max_rescans <= 10);
        assert(o.connect_timeout >= 0.2 && o.connect_timeout <= 30.0);
        assert(o.forced_mode >= -1 && o.forced_mode <= MODE_PARALLEL_TTY);
    }
}

static void fuzz_marker(unsigned long iterations)
{
    struct options o;
    char dir[] = "/tmp/fa-fuzz-markers-XXXXXX";

    memset(&o, 0, sizeof o);
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(2);
    }
    o.marker_dir = dir;
    for (unsigned long i = 0; i < iterations; i++) {
        char user[300];
        size_t n = 1 + pick(sizeof user - 2);

        for (size_t k = 0; k < n; k++)
            user[k] = (char)(1 + pick(255));
        user[n] = '\0';
        if (strchr(user, '/') || user[0] == '.')
            assert(!not_enrolled_marker(&o, user));       /* never builds a path out of those */
        else
            (void)not_enrolled_marker(&o, user);
    }
    rmdir(dir);
}

int main(int argc, char **argv)
{
    unsigned long n = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000000UL;

    if (argc > 2)
        rng ^= strtoull(argv[2], NULL, 10) * 0x2545F4914F6CDD1DULL;
    fuzz_sane_timeout();
    fuzz_parse_reply(n);
    fuzz_reader(n / 4);
    fuzz_pct_encode(n / 10);
    fuzz_parse_args(n / 10);
    fuzz_marker(n / 100);
    printf("fuzz_input: %lu iterations, no finding\n", n);
    return 0;
}
