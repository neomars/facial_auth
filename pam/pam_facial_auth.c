/* SPDX-License-Identifier: MIT
 *
 * pam_facial_auth - PAM module delegating face verification to facial-authd.
 *
 * The module never decides anything by itself: it asks the daemon (over a
 * root-owned Unix socket whose peer credentials are checked) and only returns
 * PAM_SUCCESS when the daemon answered "OK".  Every other outcome is
 * PAM_IGNORE so that the rest of the stack (pam_unix, ...) handles the
 * classic password login: a failed face scan never counts as a failed login
 * and can never lock an account.
 *
 * See docs/PROTOCOL.md for the wire protocol and the interaction modes.
 */

#define _GNU_SOURCE
#include "config.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#define _(s) dgettext(GETTEXT_PACKAGE, (s))

#define MAX_LINE 1024
#define PROTO_VERSION 1
#define SCAN_SLACK_SECONDS 3.0
#define CANCEL_JOIN_SECONDS 2
/* How long connect() may keep retrying while the daemon's accept queue is
 * full.  A full queue means the daemon is overwhelmed or no longer accepting:
 * the face is not worth a login that never completes. */
#define QUEUE_FULL_SECONDS 1.0
/* A conversation that fails sooner than this after the prompt was issued
 * cannot prompt at all (no tty...); later it means the user gave up. */
#define PROMPT_REFUSED_FAST_SECONDS 0.3

enum mode { MODE_SEQUENTIAL, MODE_PARALLEL, MODE_PARALLEL_TTY };

struct options {
    bool debug;
    bool quiet;
    bool allow_locked;
    const char *socket_path;
    const char *marker_dir;     /* NULL: fast path disabled */
    int forced_mode;            /* -1: follow the daemon */
    int max_rescans;
    double connect_timeout;     /* seconds to wait for ACCEPT/SKIP */
};

struct request {
    const char *user;
    const char *service;
    const char *tty;
    const char *rhost;
    const char *ruser;
};

enum reply_kind { REPLY_NONE, REPLY_ACCEPT, REPLY_SKIP, REPLY_STATE, REPLY_OK, REPLY_FAIL, REPLY_UNKNOWN };

struct reply {
    enum reply_kind kind;
    char mode[32];
    char reason[48];
    char phase[24];
    char seq[8];
    int step;
    double timeout;
    double score;
};

/* ------------------------------------------------------------------ utils */

static double mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void scrub_string(char *s)
{
    if (s)
        explicit_bzero(s, strlen(s));
}

#define DBG(pamh, o, ...)                                                     \
    do {                                                                      \
        if ((o)->debug)                                                       \
            pam_syslog((pamh), LOG_DEBUG, __VA_ARGS__);                       \
    } while (0)

static void bind_text(void)
{
    static bool done;
    if (!done) {
        bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
        bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
        done = true;
    }
}

static void info(pam_handle_t *pamh, const struct options *o, const char *msg)
{
    if (!o->quiet)
        (void)pam_info(pamh, "%s", msg);
}

/* A terminal frontend keeps its password prompt open while the camera works: the conversation is
 * not re-entrant, so this thread cannot use it.  The text goes straight to the terminal, on the
 * line below the prompt.  Nothing else changes: the password can still be typed (unseen, the
 * frontend owns the terminal modes) and wins, exactly as it does during the plain face scan. */
static void tty_say(int fd, const char *msg)
{
    char buf[1024];
    size_t off = 0;
    int n = snprintf(buf, sizeof buf, "\r\n%s\r\n", msg);

    if (fd < 0 || n <= 0)
        return;
    if ((size_t)n >= sizeof buf)
        n = (int)sizeof buf - 1;
    while (off < (size_t)n) {
        ssize_t w = write(fd, buf + off, (size_t)n - off);

        if (w < 0) {
            if (errno == EINTR)
                continue;
            return; /* EAGAIN (terminal stopped) or gone: the message is not worth waiting for */
        }
        off += (size_t)w;
    }
}

/* Say something to the person while the scan runs: through the terminal when a password prompt is
 * pending in it, through the conversation otherwise. */
static void tell(pam_handle_t *pamh, const struct options *o, int ttyfd, bool prompt_pending,
                 const char *msg)
{
    if (o->quiet)
        return;
    if (prompt_pending)
        tty_say(ttyfd, msg);
    else
        info(pamh, o, msg);
}

/* The head-turn test (docs/PROTOCOL.md): "left" and "right" are the user's own.  The daemon only
 * sends a code ("lr" / "rl"), the wording and its translation live here. */
static bool is_challenge(const struct reply *r)
{
    return r->kind == REPLY_STATE && !strcmp(r->phase, "challenge");
}

static const char *challenge_text(const struct reply *r)
{
    if (!strcmp(r->seq, "rl"))
        return _("Turn your head clearly to your right, then to your left, then look at the screen.");
    return _("Turn your head clearly to your left, then to your right, then look at the screen.");
}

/* "turned": the daemon saw a turn.  Telling the person lets them pace themselves and shows, when it
 * never comes, that the movement was too small (docs/PROTOCOL.md). */
static bool is_turned(const struct reply *r)
{
    return r->kind == REPLY_STATE && !strcmp(r->phase, "turned") && r->step >= 1 && r->step <= 2;
}

static const char *step_text(const struct reply *r)
{
    if (r->step == 1)
        return !strcmp(r->seq, "rl") ? _("Good. Now turn your head clearly to your left.")
                                     : _("Good. Now turn your head clearly to your right.");
    return _("Good. Now look straight at the screen.");
}

/* Why the face did not open the session.  The head-turn wording is only used when the person was
 * actually asked to turn their head ("spoof" also covers a frozen camera feed). */
static const char *failure_text(const char *reason, bool head_turn_asked)
{
    if (head_turn_asked && !strcmp(reason, "challenge"))
        return _("Head-turn test not completed.");
    if (head_turn_asked && !strcmp(reason, "spoof"))
        return _("Head-turn test failed.");
    return _("Face not recognized.");
}

/* RFC 3986 percent-encoding; the caller frees the result. */
static char *pct_encode(const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = s ? strlen(s) : 0;
    char *out = malloc(n * 3 + 1), *p = out;

    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            *p++ = (char)c;
        } else {
            *p++ = '%';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 15];
        }
    }
    *p = '\0';
    return out;
}

/* ------------------------------------------------------- option parsing */

static void parse_args(pam_handle_t *pamh, int argc, const char **argv,
                       struct options *o)
{
    o->debug = false;
    o->quiet = false;
    o->allow_locked = false;
    o->socket_path = FA_SOCKET_PATH;
    o->marker_dir = FA_MARKER_DIR;
    o->forced_mode = -1;
    o->max_rescans = 3;
    o->connect_timeout = 4.0;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "debug")) {
            o->debug = true;
        } else if (!strcmp(a, "quiet")) {
            o->quiet = true;
        } else if (!strcmp(a, "allow_locked")) {
            o->allow_locked = true;
        } else if (!strncmp(a, "socket=", 7)) {
            o->socket_path = a + 7;
        } else if (!strncmp(a, "marker_dir=", 11)) {
            o->marker_dir = strcmp(a + 11, "-") ? a + 11 : NULL;
        } else if (!strncmp(a, "mode=", 5)) {
            if (!strcmp(a + 5, "sequential"))
                o->forced_mode = MODE_SEQUENTIAL;
            else if (!strcmp(a + 5, "parallel"))
                o->forced_mode = MODE_PARALLEL;
            else if (!strcmp(a + 5, "parallel-tty"))
                o->forced_mode = MODE_PARALLEL_TTY;
            else
                pam_syslog(pamh, LOG_WARNING, "unknown mode '%s'", a + 5);
        } else if (!strncmp(a, "max_rescans=", 12)) {
            o->max_rescans = atoi(a + 12);
            if (o->max_rescans < 0 || o->max_rescans > 10)
                o->max_rescans = 3;
        } else if (!strncmp(a, "connect_timeout=", 16)) {
            double t = atof(a + 16);
            if (t >= 0.2 && t <= 30.0)
                o->connect_timeout = t;
        } else {
            pam_syslog(pamh, LOG_WARNING, "unknown option '%s'", a);
        }
    }
}

/* ------------------------------------------------- socket / line reader */

struct reader {
    int fd;
    char buf[MAX_LINE * 2];
    size_t len;
};

/* Pops one complete line into out (without the newline). */
static bool reader_pop(struct reader *rd, char *out, size_t outsz)
{
    char *nl = memchr(rd->buf, '\n', rd->len);
    size_t n;

    if (!nl)
        return false;
    n = (size_t)(nl - rd->buf);
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, rd->buf, n);
    out[n] = '\0';
    rd->len -= (size_t)(nl - rd->buf) + 1;
    memmove(rd->buf, nl + 1, rd->len);
    return true;
}

/* Reads what is available. 0: ok, -1: EOF / error / oversized line. */
static int reader_fill(struct reader *rd)
{
    ssize_t r;

    if (rd->len >= sizeof rd->buf)
        return -1;
    do {
        r = recv(rd->fd, rd->buf + rd->len, sizeof rd->buf - rd->len,
                 MSG_DONTWAIT);
    } while (r < 0 && errno == EINTR);
    if (r == 0)
        return -1;
    if (r < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    rd->len += (size_t)r;
    /* No newline although the line cannot grow any more: protocol error. */
    if (!memchr(rd->buf, '\n', rd->len) && rd->len >= MAX_LINE)
        return -1;
    return 0;
}

/* Sends everything, or gives up after `limit` seconds.  The socket is
 * non-blocking: a daemon that does not read must never block a login. */
static bool send_all(int fd, const char *buf, size_t len, double limit)
{
    double deadline = mono_now() + limit;

    while (len) {
        ssize_t w = send(fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (w < 0) {
            struct pollfd pf = { .fd = fd, .events = POLLOUT };
            double left;
            int rc;

            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                return false;
            left = deadline - mono_now();
            if (left <= 0)
                return false;
            rc = poll(&pf, 1, (int)(left * 1000.0) + 1);
            if (rc < 0 && errno == EINTR)
                continue;
            if (rc <= 0)
                return false;
            continue;
        }
        buf += w;
        len -= (size_t)w;
    }
    return true;
}

/* The daemon is trusted but not infallible: whatever it announces, the
 * module's own waits stay finite.  NaN fails both comparisons, so it falls
 * back to the default too. */
static double sane_timeout(double t)
{
    return (t >= 0.5 && t <= 60.0) ? t : 8.0;
}

static void parse_reply(const char *line, struct reply *r)
{
    char tmp[MAX_LINE], *save = NULL, *tok;

    memset(r, 0, sizeof *r);
    r->kind = REPLY_UNKNOWN;
    snprintf(tmp, sizeof tmp, "%s", line);

    tok = strtok_r(tmp, " ", &save);
    if (!tok)
        return;
    if (!strcmp(tok, "ACCEPT"))
        r->kind = REPLY_ACCEPT;
    else if (!strcmp(tok, "SKIP"))
        r->kind = REPLY_SKIP;
    else if (!strcmp(tok, "STATE"))
        r->kind = REPLY_STATE;
    else if (!strcmp(tok, "OK"))
        r->kind = REPLY_OK;
    else if (!strcmp(tok, "FAIL"))
        r->kind = REPLY_FAIL;
    else
        return;

    while ((tok = strtok_r(NULL, " ", &save)) != NULL) {
        char *eq = strchr(tok, '=');
        if (!eq)
            continue;
        *eq++ = '\0';
        if (!strcmp(tok, "mode"))
            snprintf(r->mode, sizeof r->mode, "%s", eq);
        else if (!strcmp(tok, "reason"))
            snprintf(r->reason, sizeof r->reason, "%s", eq);
        else if (!strcmp(tok, "phase"))
            snprintf(r->phase, sizeof r->phase, "%s", eq);
        else if (!strcmp(tok, "seq"))
            snprintf(r->seq, sizeof r->seq, "%s", eq);
        else if (!strcmp(tok, "step"))
            r->step = (atoi(eq) >= 0 && atoi(eq) <= 9) ? atoi(eq) : 0;
        else if (!strcmp(tok, "timeout"))
            r->timeout = atof(eq);
        else if (!strcmp(tok, "score"))
            r->score = atof(eq);
    }
}

/* The daemon is the only thing that may say "OK": check who we talk to. */
static bool peer_is_trusted(pam_handle_t *pamh, const struct options *o, int fd)
{
    struct ucred cr;
    socklen_t l = sizeof cr;
    struct passwd *pw;

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &l) != 0)
        return false;
    if (cr.uid == 0)
        return true;
    pw = pam_modutil_getpwnam(pamh, FA_SERVICE_USER);
    if (pw && cr.uid == pw->pw_uid)
        return true;
    pam_syslog(pamh, LOG_ERR, "refusing socket %s: untrusted peer uid %u",
               o->socket_path, (unsigned)cr.uid);
    return false;
}

static int connect_daemon(pam_handle_t *pamh, const struct options *o)
{
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    struct stat st;
    double deadline;
    int fd;

    if (strlen(o->socket_path) >= sizeof sa.sun_path)
        return -1;
    strcpy(sa.sun_path, o->socket_path);

    if (lstat(o->socket_path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        DBG(pamh, o, "no daemon socket at %s", o->socket_path);
        return -1;
    }
    /* Non-blocking from the start: a blocking connect() on a Unix socket waits
     * for ever when the daemon's accept queue is full (daemon wedged, or
     * flooded by a local user), and nobody could log in any more. */
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    deadline = mono_now() + QUEUE_FULL_SECONDS;
    while (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        /* EAGAIN: queue full.  Retry briefly: a busy but alive daemon drains it. */
        if (errno == EAGAIN && mono_now() < deadline) {
            (void)poll(NULL, 0, 20);
            continue;
        }
        if (errno == EINTR)
            continue;
        DBG(pamh, o, "connect(%s): %s", o->socket_path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!peer_is_trusted(pamh, o, fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Waits for one line (or EOF/timeout).  wake_fd (>= 0) is watched as well.
 * Returns 1: line popped, 0: timeout, -1: EOF/error, 2: wake_fd readable. */
static int wait_line(struct reader *rd, int wake_fd, int timeout_ms, char *out,
                     size_t outsz)
{
    for (;;) {
        struct pollfd pf[2];
        nfds_t n = 0;
        int rc;

        if (reader_pop(rd, out, outsz))
            return 1;
        if (rd->fd >= 0) {
            pf[n].fd = rd->fd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        }
        if (wake_fd >= 0) {
            pf[n].fd = wake_fd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        }
        if (!n)
            return 0;
        rc = poll(pf, n, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rc == 0)
            return 0;
        for (nfds_t i = 0; i < n; i++) {
            if (!pf[i].revents)
                continue;
            if (pf[i].fd == wake_fd && wake_fd >= 0 && pf[i].fd != rd->fd)
                return 2;
            if (pf[i].fd == rd->fd) {
                if (reader_fill(rd) != 0) {
                    /* deliver buffered lines before reporting EOF */
                    if (reader_pop(rd, out, outsz))
                        return 1;
                    return -1;
                }
            }
        }
    }
}

/* ------------------------------------------------------ prompt thread */

struct prompter {
    pthread_t th;
    bool started;
    pthread_mutex_t mu;
    bool done;
    bool abandoned;
    int rc;
    char *answer;
    int wake[2];
    pam_handle_t *pamh;
    double issued_at;
    double elapsed;
};

static void prompter_destroy(struct prompter *p)
{
    if (!p)
        return;
    if (p->answer) {
        scrub_string(p->answer);
        free(p->answer);
    }
    if (p->wake[0] >= 0)
        close(p->wake[0]);
    if (p->wake[1] >= 0)
        close(p->wake[1]);
    pthread_mutex_destroy(&p->mu);
    free(p);
}

static void *prompter_main(void *arg)
{
    struct prompter *p = arg;
    char *resp = NULL;
    int rc, old;
    bool destroy;

    /* The prompt text must stay the stock "Password: " so that frontends such
     * as sudo recognise it and substitute their own prompt. */
    rc = pam_prompt(p->pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s",
                    dgettext("Linux-PAM", "Password: "));

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    pthread_mutex_lock(&p->mu);
    destroy = p->abandoned;
    if (!destroy) {
        p->rc = rc;
        p->answer = resp;
        resp = NULL;
        p->elapsed = mono_now() - p->issued_at;
        p->done = true;
        (void)!write(p->wake[1], "x", 1);
    }
    pthread_mutex_unlock(&p->mu);
    if (resp) {
        scrub_string(resp);
        free(resp);
    }
    if (destroy)
        prompter_destroy(p); /* nobody waits for us any more */
    return NULL;
}

static struct prompter *prompter_start(pam_handle_t *pamh)
{
    struct prompter *p = calloc(1, sizeof *p);

    if (!p)
        return NULL;
    p->wake[0] = p->wake[1] = -1;
    p->pamh = pamh;
    p->issued_at = mono_now();
    pthread_mutex_init(&p->mu, NULL);
    if (pipe2(p->wake, O_CLOEXEC | O_NONBLOCK) != 0 ||
        pthread_create(&p->th, NULL, prompter_main, p) != 0) {
        prompter_destroy(p);
        return NULL;
    }
    p->started = true;
    return p;
}

/* The prompt thread is stuck in the application's conversation function and
 * cannot be interrupted portably.  Two strategies:
 *  - cancel (terminal frontends): a blocked read(2) on the tty would steal the
 *    keystrokes meant for the command that sudo/su is about to run;
 *  - abandon (graphical frontends): the thread is left to finish whenever the
 *    frontend answers; cancelling a thread inside GLib/D-Bus code is unsafe.
 *
 * Returns true when the thread is really gone.  When it is not (abandoned, or
 * a conversation that ignores cancellation) the conversation function may still
 * be running: the caller must NOT call it again from this thread. */
static bool prompter_stop(struct prompter *p, bool cancel)
{
    bool join = false;
    pthread_t th;

    pthread_mutex_lock(&p->mu);
    th = p->th; /* copied while the thread cannot have freed p yet */
    if (p->done)
        join = true;
    else if (cancel)
        join = true;
    else
        p->abandoned = true;
    pthread_mutex_unlock(&p->mu);

    if (!join) {
        /* Abandoned: it frees p itself when it returns, and nobody will join
         * it, so let the system reclaim its stack when it ends too. */
        pthread_detach(th);
        return false;
    }

    if (cancel) {
        pthread_mutex_lock(&p->mu);
        if (!p->done)
            pthread_cancel(p->th);
        pthread_mutex_unlock(&p->mu);
    }
    {
        struct timespec dl;

        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += CANCEL_JOIN_SECONDS;
        if (pthread_timedjoin_np(p->th, NULL, &dl) != 0) {
            /* Could not stop it: leave it running, it frees itself. */
            pthread_mutex_lock(&p->mu);
            if (!p->done) {
                p->abandoned = true;
                pthread_mutex_unlock(&p->mu);
                pthread_detach(th);
                return false;
            }
            pthread_mutex_unlock(&p->mu);
            /* it finished right after the timeout: join for real */
            pthread_join(p->th, NULL);
        }
    }
    prompter_destroy(p);
    return true;
}

/* pthread_cancel() needs libgcc_s for the forced unwind; loading it for the
 * first time while cancelling (inside a sandboxed process) can abort. */
static bool preload_unwinder(void)
{
    static void *h;

    if (!h)
        h = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_NODELETE);
    return h != NULL;
}

/* ------------------------------------------------------- one scan round */

enum round_result {
    ROUND_SUCCESS,   /* face recognised */
    ROUND_PASSWORD,  /* a password was typed and stored in PAM_AUTHTOK */
    ROUND_RESCAN,    /* empty password: the user asks to try the face again */
    ROUND_ABORT,     /* the user gave up (Ctrl-C, Cancel): stop everything */
    ROUND_NONE       /* nothing: let the stack continue */
};

static enum round_result run_sequential(pam_handle_t *pamh,
                                        const struct options *o,
                                        struct reader *rd, double scan_timeout,
                                        double *score)
{
    char line[MAX_LINE];
    double deadline = mono_now() + scan_timeout + SCAN_SLACK_SECONDS;
    char fail_reason[sizeof ((struct reply *)0)->reason] = "";
    bool asked = false;
    int shown = 0;

    info(pamh, o, _("Looking for your face..."));
    for (;;) {
        double left = deadline - mono_now();
        struct reply r;
        int rc;

        if (left <= 0)
            break;
        rc = wait_line(rd, -1, (int)(left * 1000.0) + 1, line, sizeof line);
        if (rc <= 0)
            break;
        parse_reply(line, &r);
        if (r.kind == REPLY_OK) {
            *score = r.score;
            return ROUND_SUCCESS;
        }
        if (r.kind == REPLY_FAIL) {
            DBG(pamh, o, "face scan failed: %s", r.reason);
            snprintf(fail_reason, sizeof fail_reason, "%s", r.reason);
            break;
        }
        if (is_challenge(&r)) {
            asked = true;
            info(pamh, o, challenge_text(&r));
            if (r.timeout > 0.0)  /* the head turn has its own, shorter clock */
                deadline = mono_now() + sane_timeout(r.timeout) + SCAN_SLACK_SECONDS;
        } else if (is_turned(&r) && asked && r.step > shown) {
            shown = r.step;
            info(pamh, o, step_text(&r));
        }
    }
    if (asked && !fail_reason[0])  /* the daemon went silent or vanished during the head turn */
        snprintf(fail_reason, sizeof fail_reason, "challenge");
    info(pamh, o, failure_text(fail_reason, asked));
    return ROUND_NONE;
}

static enum round_result run_parallel(pam_handle_t *pamh,
                                      const struct options *o,
                                      struct reader *rd, double scan_timeout,
                                      bool cancel_prompt, double *score)
{
    char line[MAX_LINE];
    struct prompter *p;
    sigset_t all, saved;
    struct termios tio;
    int ttyfd = -1;
    bool have_tio = false;
    bool face_pending = true, face_ok = false;
    bool prompt_active = true, got_answer = false, aborted = false;
    bool masked = false;
    /* The head-turn test (terminal frontends only): its instructions are written to the terminal
     * below the password prompt, which stays open (see tty_say()). */
    bool challenge_shown = false;
    int steps_shown = 0;
    double deadline;
    enum round_result res = ROUND_NONE;

    if (cancel_prompt) {
        if (!preload_unwinder()) {
            DBG(pamh, o, "libgcc_s unavailable: falling back to sequential");
            return run_sequential(pamh, o, rd, scan_timeout, score);
        }
        ttyfd = open("/dev/tty", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
        if (ttyfd >= 0 && tcgetattr(ttyfd, &tio) == 0)
            have_tio = true;
    }

    info(pamh, o, _("Looking for your face... (or type your password)"));

    /* Conversation callbacks must never run concurrently: the info message
     * above is done, from now on only the prompt thread talks to the user. */
    p = prompter_start(pamh);
    if (!p) {
        if (ttyfd >= 0)
            close(ttyfd);
        return run_sequential(pamh, o, rd, scan_timeout, score);
    }

    /* Signals (Ctrl-C, ...) must reach the prompt thread, whose blocked read
     * then fails with EINTR exactly as in a single-threaded program. */
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &saved);
    masked = true;

    deadline = mono_now() + scan_timeout + SCAN_SLACK_SECONDS;
    for (;;) {
        int rc, timeout_ms = -1;

        if (face_ok)
            break;
        if (prompt_active) {
            bool done, valid;
            double took;

            pthread_mutex_lock(&p->mu);
            done = p->done;
            valid = p->done && p->rc == PAM_SUCCESS && p->answer;
            took = p->elapsed;
            pthread_mutex_unlock(&p->mu);
            if (done && valid) {
                got_answer = true;
                break;
            }
            if (done && took >= PROMPT_REFUSED_FAST_SECONDS) {
                /* Ctrl-C / Cancel: the user is gone, do not keep the camera
                 * running nor wait for the scan to time out. */
                DBG(pamh, o, "password prompt aborted after %.1fs", took);
                aborted = true;
                break;
            }
            if (done) {
                /* The frontend cannot prompt (no tty, ...): the face is the
                 * only way left, keep scanning. */
                DBG(pamh, o, "conversation refused the password prompt");
                prompt_active = false;
                /* No thread is left to receive signals: take them back. */
                pthread_sigmask(SIG_SETMASK, &saved, NULL);
                masked = false;
            }
        }
        if (face_pending) {
            double left = deadline - mono_now();

            if (left <= 0) {
                DBG(pamh, o, "daemon did not answer in time");
                face_pending = false;
                close(rd->fd);
                rd->fd = -1;
                if (challenge_shown)
                    tell(pamh, o, ttyfd, prompt_active, failure_text("challenge", true));
            } else {
                timeout_ms = (int)(left * 1000.0) + 1;
            }
        }
        if (!prompt_active && !face_pending)
            break; /* nothing left to wait for */

        rc = wait_line(rd, prompt_active ? p->wake[0] : -1, timeout_ms, line,
                       sizeof line);
        if (rc == 1) {
            struct reply r;

            parse_reply(line, &r);
            if (r.kind == REPLY_OK) {
                face_ok = true;
                *score = r.score;
            } else if (r.kind == REPLY_FAIL) {
                DBG(pamh, o, "face scan failed: %s", r.reason);
                face_pending = false;
                close(rd->fd);
                rd->fd = -1;
                if (challenge_shown)
                    tell(pamh, o, ttyfd, prompt_active, failure_text(r.reason, true));
            } else if (is_challenge(&r) && cancel_prompt && !challenge_shown) {
                challenge_shown = true;
                tell(pamh, o, ttyfd, prompt_active, challenge_text(&r));
                /* The head turn has its own clock: do not wait for a silent daemon longer than it
                 * can last, however much of the scan budget was left. */
                if (r.timeout > 0.0)
                    deadline = mono_now() + sane_timeout(r.timeout) + SCAN_SLACK_SECONDS;
            } else if (is_turned(&r) && challenge_shown && r.step > steps_shown) {
                steps_shown = r.step;
                tell(pamh, o, ttyfd, prompt_active, step_text(&r));
            }
        } else if (rc < 0 && face_pending) {
            /* daemon vanished: only the password remains */
            face_pending = false;
            close(rd->fd);
            rd->fd = -1;
            if (challenge_shown)
                tell(pamh, o, ttyfd, prompt_active, failure_text("challenge", true));
        } else if (rc == 2) {
            char drain[8];

            (void)!read(p->wake[0], drain, sizeof drain);
        }
    }

    if (masked)
        pthread_sigmask(SIG_SETMASK, &saved, NULL);

    if (face_ok) {
        /* The face won (also when the password finished at the same time). */
        bool gone = false;

        if (p) {
            gone = prompter_stop(p, cancel_prompt);
            if (cancel_prompt && ttyfd >= 0) {
                if (have_tio)
                    tcsetattr(ttyfd, TCSAFLUSH, &tio); /* drops half-typed input */
                (void)!write(ttyfd, "\n", 1);
            }
        }
        /* Only talk through the conversation when no other thread is inside it. */
        if (cancel_prompt && gone)
            info(pamh, o, _("Face recognized."));
        res = ROUND_SUCCESS;
        goto out;
    }

    /* No face: stop the scan if it still runs, then look at the password. */
    if (rd->fd >= 0) {
        close(rd->fd);
        rd->fd = -1;
    }
    if (aborted)
        res = ROUND_ABORT;
    if (got_answer) {
        const char *answer = NULL;

        pthread_mutex_lock(&p->mu);
        answer = p->answer;
        pthread_mutex_unlock(&p->mu);
        if (answer && answer[0] != '\0') {
            pam_set_item(pamh, PAM_AUTHTOK, answer);
            res = ROUND_PASSWORD;
        } else {
            res = ROUND_RESCAN; /* empty answer: "try my face again" */
        }
    }
    if (p)
        prompter_stop(p, cancel_prompt);

out:
    if (ttyfd >= 0)
        close(ttyfd);
    return res;
}

static enum round_result do_round(pam_handle_t *pamh, const struct options *o,
                                  const struct request *rq, double *score,
                                  bool *skipped)
{
    char line[MAX_LINE], *u = NULL, *s = NULL, *t = NULL, *h = NULL, *ru = NULL;
    char req[MAX_LINE];
    struct reader rd;
    struct reply r;
    enum round_result res = ROUND_NONE;
    int fd, rc, mode;

    *skipped = false;
    fd = connect_daemon(pamh, o);
    if (fd < 0) {
        *skipped = true;
        return ROUND_NONE;
    }
    memset(&rd, 0, sizeof rd);
    rd.fd = fd;

    u = pct_encode(rq->user);
    s = pct_encode(rq->service);
    t = pct_encode(rq->tty);
    h = pct_encode(rq->rhost);
    ru = pct_encode(rq->ruser);
    if (!u || !s || !t || !h || !ru) {
        *skipped = true;
        goto done;
    }
    rc = snprintf(req, sizeof req,
                  "VERIFY v=%d user=%s service=%s tty=%s rhost=%s ruser=%s\n",
                  PROTO_VERSION, u, s, t, h, ru);
    if (rc < 0 || (size_t)rc >= sizeof req ||
        !send_all(fd, req, (size_t)rc, o->connect_timeout)) {
        *skipped = true;
        goto done;
    }

    rc = wait_line(&rd, -1, (int)(o->connect_timeout * 1000.0), line,
                   sizeof line);
    if (rc != 1) {
        DBG(pamh, o, "no answer from the daemon");
        *skipped = true;
        goto done;
    }
    parse_reply(line, &r);
    if (r.kind == REPLY_SKIP) {
        DBG(pamh, o, "daemon skipped face auth: %s", r.reason);
        *skipped = true;
        goto done;
    }
    if (r.kind != REPLY_ACCEPT) {
        pam_syslog(pamh, LOG_WARNING, "unexpected daemon reply: %.60s", line);
        *skipped = true;
        goto done;
    }

    if (!strcmp(r.mode, "parallel"))
        mode = MODE_PARALLEL;
    else if (!strcmp(r.mode, "parallel-tty"))
        mode = MODE_PARALLEL_TTY;
    else
        mode = MODE_SEQUENTIAL;
    if (o->forced_mode >= 0)
        mode = o->forced_mode;
    r.timeout = sane_timeout(r.timeout);
    DBG(pamh, o, "scan accepted: mode=%d timeout=%.1f", mode, r.timeout);

    if (mode == MODE_SEQUENTIAL)
        res = run_sequential(pamh, o, &rd, r.timeout, score);
    else
        res = run_parallel(pamh, o, &rd, r.timeout, mode == MODE_PARALLEL_TTY,
                           score);
done:
    if (rd.fd >= 0)
        close(rd.fd);
    free(u);
    free(s);
    free(t);
    free(h);
    free(ru);
    return res;
}

/* ----------------------------------------------------------- pre-checks */

static bool is_loopback_host(const char *h)
{
    return !h || !*h || !strcmp(h, "localhost") || !strcmp(h, "127.0.0.1") ||
           !strcmp(h, "::1") || !strcmp(h, "localhost.localdomain");
}

/* sudo/su started from an ssh session inherit these: whoever types there is not
 * in front of the local camera, so a face would prove nothing. */
static bool inside_ssh_session(void)
{
    return getenv("SSH_CONNECTION") || getenv("SSH_CLIENT") || getenv("SSH_TTY");
}

static bool not_enrolled_marker(const struct options *o, const char *user)
{
    char path[PATH_MAX];

    if (!o->marker_dir || !*o->marker_dir)
        return false;
    if (strchr(user, '/') || user[0] == '.')
        return false; /* let the daemon refuse it */
    if (snprintf(path, sizeof path, "%s/%s", o->marker_dir, user) >=
        (int)sizeof path)
        return false;
    if (access(path, F_OK) == 0)
        return false;
    return errno == ENOENT;
}

static bool account_is_locked(pam_handle_t *pamh, const char *user)
{
    struct spwd *sp = pam_modutil_getspnam(pamh, user);

    if (!sp || !sp->sp_pwdp)
        return false; /* cannot tell (not root): the daemon/stack will */
    return sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*';
}

/* ------------------------------------------------------- PAM entry point */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    struct options o;
    struct request rq;
    const char *user = NULL, *service = NULL, *tty = NULL, *rhost = NULL,
               *ruser = NULL, *authtok = NULL;
    struct passwd *pw;
    int rescans = 0;

    (void)flags;
    bind_text();
    parse_args(pamh, argc, argv, &o);

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS ||
        !user || !*user)
        return PAM_IGNORE; /* nobody to look for yet: pam_unix will ask */
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    pam_get_item(pamh, PAM_TTY, (const void **)&tty);
    pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
    pam_get_item(pamh, PAM_RUSER, (const void **)&ruser);

    /* Someone already collected a password: do not second-guess the stack. */
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok) ==
            PAM_SUCCESS &&
        authtok && *authtok)
        return PAM_IGNORE;

    if (!is_loopback_host(rhost)) {
        DBG(pamh, &o, "remote login (%s): no face authentication", rhost);
        return PAM_IGNORE;
    }
    if (inside_ssh_session()) {
        DBG(pamh, &o, "inside an ssh session: no face authentication");
        return PAM_IGNORE;
    }
    pw = pam_modutil_getpwnam(pamh, user);
    if (!pw)
        return PAM_IGNORE;
    if (not_enrolled_marker(&o, user))
        return PAM_IGNORE;
    if (!o.allow_locked && account_is_locked(pamh, user)) {
        DBG(pamh, &o, "account %s is locked: no face authentication", user);
        return PAM_IGNORE;
    }

    rq.user = user;
    rq.service = service ? service : "";
    rq.tty = tty ? tty : "";
    rq.rhost = rhost ? rhost : "";
    rq.ruser = ruser ? ruser : "";

    for (;;) {
        double score = 0.0;
        bool skipped = false;
        enum round_result r = do_round(pamh, &o, &rq, &score, &skipped);

        if (r == ROUND_SUCCESS) {
            pam_syslog(pamh, LOG_NOTICE,
                       "face authentication succeeded for %s (score %.2f)",
                       user, score);
            return PAM_SUCCESS;
        }
        if (r == ROUND_RESCAN && rescans < o.max_rescans) {
            rescans++;
            continue;
        }
        if (r == ROUND_ABORT)
            return PAM_CONV_ERR; /* with conv_err=die the stack stops here */
        return PAM_IGNORE; /* password (PAM_AUTHTOK set) or nothing */
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
