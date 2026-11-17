/* SPDX-License-Identifier: MIT
 *
 * pamtest - a scriptable PAM application used to exercise pam_facial_auth.
 *
 *   pamtest [options] SERVICE USER
 *     --answer DELAY_MS:TEXT   answer for the next password prompt (repeatable)
 *     --refuse-prompts         conversation fails (PAM_CONV_ERR) on prompts
 *     --stubborn               conversation ignores pthread_cancel() (GUI-like)
 *     --stubborn-ms N          how long a stubborn conversation blocks (def 1500)
 *     --rhost HOST / --ruser S / --tty DEV
 *     --post-sleep MS          sleep after pam_authenticate before pam_end
 *
 * Every conversation event is printed on stdout with the elapsed time, so the
 * Python tests can assert on ordering.  Two threads inside the conversation at
 * the same time is a bug of the module and is reported loudly.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <security/pam_appl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct answer {
    int delay_ms;
    char *text;
};

static struct answer answers[16];
static int n_answers;
static int next_answer;
static int in_flight;
static int refuse_prompts;
static int stubborn;
static int stubborn_ms = 1500;
static double t0;
static pthread_mutex_t out_mu = PTHREAD_MUTEX_INITIALIZER;

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void say(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(const char *tag, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&out_mu);
    printf("%s %d %s\n", tag, (int)(now() - t0), buf);
    fflush(stdout);
    pthread_mutex_unlock(&out_mu);
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0)
        ;
}

static void on_cancel(void *arg)
{
    (void)arg;
    __atomic_sub_fetch(&in_flight, 1, __ATOMIC_SEQ_CST);
    say("CONV-CANCELLED", "-");
}

static int conv(int n, const struct pam_message **msg,
                struct pam_response **resp, void *ud)
{
    int flight = __atomic_add_fetch(&in_flight, 1, __ATOMIC_SEQ_CST);
    volatile int refused = 0;

    (void)ud;
    if (flight > 1)
        say("ERROR", "concurrent conversation calls (%d)", flight);
    *resp = calloc((size_t)n, sizeof **resp);

    /* pthread_cleanup_push/pop open and close a block: no early return. */
    pthread_cleanup_push(on_cancel, NULL);
    for (int i = 0; i < n && !refused; i++) {
        int style = msg[i]->msg_style;

        if (style == PAM_TEXT_INFO || style == PAM_ERROR_MSG) {
            say("INFO", "%s", msg[i]->msg);
        } else if (style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON) {
            int idx, old;

            say("PROMPT", "%s", msg[i]->msg);
            if (refuse_prompts) {
                refused = 1;
                break;
            }
            idx = __atomic_fetch_add(&next_answer, 1, __ATOMIC_SEQ_CST);
            if (idx < n_answers) {
                if (stubborn)
                    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
                sleep_ms(answers[idx].delay_ms);
                (*resp)[i].resp = strdup(answers[idx].text);
                say("ANSWER", "%d", idx);
                if (stubborn)
                    pthread_setcancelstate(old, &old);
            } else if (stubborn) {
                /* A frontend that answers late and cannot be interrupted. */
                pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
                sleep_ms(stubborn_ms);
                (*resp)[i].resp = strdup("late-answer");
                say("LATE-ANSWER", "%d", idx);
                pthread_setcancelstate(old, &old);
            } else {
                /* The user never types anything. */
                for (;;)
                    sleep_ms(100);
            }
        }
    }
    pthread_cleanup_pop(0);

    __atomic_sub_fetch(&in_flight, 1, __ATOMIC_SEQ_CST);
    if (refused) {
        free(*resp);
        *resp = NULL;
        return PAM_CONV_ERR;
    }
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    struct pam_conv c = { conv, NULL };
    pam_handle_t *h = NULL;
    const char *rhost = NULL, *ruser = NULL, *tty = NULL;
    int post_sleep = 0, rc, i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--answer") && i + 1 < argc && n_answers < 16) {
            char *a = argv[++i], *colon = strchr(a, ':');
            if (!colon)
                return 64;
            *colon = '\0';
            answers[n_answers].delay_ms = atoi(a);
            answers[n_answers].text = colon + 1;
            n_answers++;
        } else if (!strcmp(argv[i], "--refuse-prompts")) {
            refuse_prompts = 1;
        } else if (!strcmp(argv[i], "--stubborn")) {
            stubborn = 1;
        } else if (!strcmp(argv[i], "--stubborn-ms") && i + 1 < argc) {
            stubborn_ms = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--rhost") && i + 1 < argc) {
            rhost = argv[++i];
        } else if (!strcmp(argv[i], "--ruser") && i + 1 < argc) {
            ruser = argv[++i];
        } else if (!strcmp(argv[i], "--tty") && i + 1 < argc) {
            tty = argv[++i];
        } else if (!strcmp(argv[i], "--post-sleep") && i + 1 < argc) {
            post_sleep = atoi(argv[++i]);
        } else {
            break;
        }
    }
    if (argc - i != 2) {
        fprintf(stderr, "usage: pamtest [options] SERVICE USER\n");
        return 64;
    }
    t0 = now();
    rc = pam_start(argv[i], argv[i + 1], &c, &h);
    if (rc != PAM_SUCCESS) {
        say("ERROR", "pam_start: %d", rc);
        return 2;
    }
    if (rhost)
        pam_set_item(h, PAM_RHOST, rhost);
    if (ruser)
        pam_set_item(h, PAM_RUSER, ruser);
    if (tty)
        pam_set_item(h, PAM_TTY, tty);

    rc = pam_authenticate(h, 0);
    say("RESULT", "%d %s", rc, pam_strerror(h, rc));
    if (post_sleep > 0)
        sleep_ms(post_sleep);
    pam_end(h, rc);
    say("END", "-");
    return rc == PAM_SUCCESS ? 0 : 1;
}
