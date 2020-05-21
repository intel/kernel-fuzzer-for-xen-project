#include <signal.h>
#include <stdbool.h>
#include <stddef.h>

static struct sigaction act;
extern int interrupted;
extern bool loopmode;

static void close_handler(int sig)
{
    interrupted = sig;
    loopmode = false;
}

void setup_handlers(void)
{
    act.sa_handler = close_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
}
