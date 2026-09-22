/* R55-SK-1 probe: map Linux poll() revents for TCP peer states, to design
 * the wait_events fix without breaking the clean-FIN half-close path. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

static void dump(const char *tag, int fd, short events, int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int pr = poll(&pfd, 1, timeout);
    printf("  %-46s events=0x%-4x -> pr=%d revents=0x%x (IN=%d OUT=%d ERR=%d HUP=%d NVAL=%d)\n",
           tag, events, pr, pfd.revents,
           !!(pfd.revents & POLLIN), !!(pfd.revents & POLLOUT),
           !!(pfd.revents & POLLERR), !!(pfd.revents & POLLHUP),
           !!(pfd.revents & POLLNVAL));
}

int main(void)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    bind(lfd,(struct sockaddr*)&sa,sizeof sa); listen(lfd,8);
    socklen_t sl=sizeof sa; getsockname(lfd,(struct sockaddr*)&sa,&sl);

    /* ---- case 1: peer sends FIN (shutdown SHUT_WR), we read it to EOF ---- */
    printf("== clean FIN (SHUT_WR), read to EOF ==\n");
    int c1 = socket(AF_INET, SOCK_STREAM, 0); connect(c1,(struct sockaddr*)&sa,sizeof sa);
    int a1 = accept(lfd,NULL,NULL);
    /* send some data, then FIN */
    send(c1,"hello",5,0); shutdown(c1, SHUT_WR); usleep(150000);
    char buf[64];
    dump("before reading (data+FIN pending)", a1, POLLIN, 500);
    int rr = recv(a1, buf, sizeof buf, 0);
    printf("  recv1=%d (%.*s)\n", rr, rr>0?rr:0, buf);
    int rr2 = recv(a1, buf, sizeof buf, 0);
    printf("  recv2 (EOF) = %d errno=%d\n", rr2, errno);
    dump("after EOF, events=0", a1, 0, 400);
    dump("after EOF, events=POLLIN", a1, POLLIN, 400);
    dump("after EOF, events=POLLOUT (writable?)", a1, POLLOUT, 400);
    /* can we still write? (client did SHUT_WR only -> its read side open) */
    ssize_t w = send(a1, "reply", 5, 0);
    printf("  send after peer SHUT_WR = %zd errno=%d\n", w, errno);
    dump("after write, events=POLLOUT", a1, POLLOUT, 400);
    dump("after write, events=0", a1, 0, 400);
    close(c1); close(a1);

    /* ---- case 2: FULL clean close of peer (close not linger 0) ---- */
    printf("== full clean close (close, FIN) ==\n");
    int c2 = socket(AF_INET, SOCK_STREAM, 0); connect(c2,(struct sockaddr*)&sa,sizeof sa);
    int a2 = accept(lfd,NULL,NULL);
    send(c2,"data",4,0); close(c2); usleep(150000);
    rr = recv(a2, buf, sizeof buf, 0);
    printf("  recv1=%d\n", rr);
    rr2 = recv(a2, buf, sizeof buf, 0);
    printf("  recv2(EOF)=%d\n", rr2);
    dump("full clean close: after EOF events=0", a2, 0, 400);
    dump("full clean close: events=POLLIN", a2, POLLIN, 400);
    dump("full clean close: events=POLLOUT", a2, POLLOUT, 400);
    ssize_t w2 = send(a2, "late", 4, 0);
    printf("  send after full close = %zd errno=%d (peer may have closed read side)\n", w2, errno);
    close(c2); close(a2);

    /* ---- case 3: RST (SO_LINGER 0) -- reproduce ---- */
    printf("== RST (SO_LINGER{1,0}) ==\n");
    int c3 = socket(AF_INET, SOCK_STREAM, 0); connect(c3,(struct sockaddr*)&sa,sizeof sa);
    int a3 = accept(lfd,NULL,NULL);
    struct linger lg = {1,0}; setsockopt(c3, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(c3); usleep(150000);
    dump("RST: events=0", a3, 0, 400);
    dump("RST: events=POLLIN", a3, POLLIN, 400);
    dump("RST: events=POLLOUT", a3, POLLOUT, 400);
    rr = recv(a3, buf, sizeof buf, 0);
    printf("  recv after RST = %d errno=%d (%s)\n", rr, errno, strerror(errno));
    close(a3);

    /* ---- case 4: half-close where client STILL READS (SHUT_WR only, keeps reading):
     *  -> our writes must keep succeeding and NO ERR/HUP may be reported ---- */
    printf("== client SHUT_WR (half-close), client still reading ==\n");
    int c4 = socket(AF_INET, SOCK_STREAM, 0); connect(c4,(struct sockaddr*)&sa,sizeof sa);
    int a4 = accept(lfd,NULL,NULL);
    shutdown(c4, SHUT_WR); usleep(100000);
    dump("before EOF consumed, events=POLLIN", a4, POLLIN, 400);
    rr = recv(a4, buf, sizeof buf, 0);
    printf("  recv(EOF)=%d\n", rr);
    dump("EOF consumed, events=0", a4, 0, 400);
    dump("EOF consumed, events=POLLIN", a4, POLLIN, 400);
    for (int i=0;i<3;i++) {
        ssize_t w4 = send(a4, "stream", 6, 0);
        printf("  send #%d = %zd errno=%d\n", i, w4, errno);
        dump("after write, events=POLLOUT", a4, POLLOUT, 400);
        dump("after write, events=0", a4, 0, 400);
    }
    close(c4); close(a4);

    close(lfd);
    return 0;
}
