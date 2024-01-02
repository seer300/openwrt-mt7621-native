/*****************************************************************************
* $File:   watchdog.c
*
* $Author: Hua Shao
* $Date:   Feb, 2014
*
* The dog needs feeding.......
*
*****************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/watchdog.h>

#if 0
#define TRACE(...) \
    do { \
        fprintf(stderr, "<trace> "__VA_ARGS__); \
        fprintf(stderr, " %s, L%d.\n", __FUNCTION__, __LINE__); \
    } while(0)
#else
#define TRACE(...)
#endif


static int _running = 1;
static int fd = 0;

void sigusr1_handler(int arg)
{
    _running = 0;
}

void sigterm_handler(int arg)
{
    int ret;
    int opt = 0;
    _running = 0;
    opt = WDIOS_DISABLECARD;
    ret = ioctl(fd, WDIOC_SETOPTIONS, &opt);
    if ( ret == EINTR )
        ioctl(fd, WDIOC_SETOPTIONS, &opt);
    TRACE("WDIOS_DISABLECARD %d", ret);
}


int main(int argc, char *const argv[])
{
    pid_t pid = 0;
    int ret = 0;

    TRACE("");

    pid = fork();
    if (pid < 0)
    {
        TRACE("fork fail!");
        fprintf(stderr, "fork fail! %s!\n", strerror(errno));
        return -1;
    }
    if (pid>0)
    {
        fprintf(stderr, "watchdog fork, parent exit!\n");
        exit(0);
    }

    /* avoid reseting syste before fully inited. */
    TRACE("sleep");
    sleep(10);
    TRACE("wake watchdog up");

    /* open the device */
    fd = open("/dev/watchdog", O_WRONLY);
    if ( fd == -1 )
    {
        fprintf(stderr, "open /dev/watchdog fail! %s!\n", strerror(errno));
        exit(1);
    }

    TRACE("");
    signal(SIGTERM, sigterm_handler);
    signal(SIGUSR1, sigusr1_handler);

    /* main loop: feeds the dog every <tint> seconds */
    while(_running)
    {
        if(write(fd, "\0", 1)<0)
        {
            TRACE("");
        }
        TRACE("");
        sleep(1);
    }

    fprintf(stderr, "wdt app get killed.\n");

__retry:
    if (close(fd) == -1)
    {
        TRACE("");
    }
}


