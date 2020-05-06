#include "private.h"

static struct sigaction act;
extern int interrupted;
extern vmi_instance_t vmi;
extern GSList *events;

static void close_handler(int sig)
{
    interrupted = sig;
}

void event_free(vmi_event_t *event, status_t status)
{
    (void)status;
    g_free(event);
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
