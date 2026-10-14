#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_PKT 65535
#define MAX_NAME 255
#define MAX_LBL 63
#define MAX_JMP 16
#define OUT_NAME 1100
#define EDNS_SZ 1232

typedef struct {
    uint16_t cod;
    const char *nm;
} tent_t;

static const tent_t TTAB[] = {
    {1, "A"}, {2, "NS"}, {5, "CNAME"}, {6, "SOA"}, {12, "PTR"}, {15, "MX"},
    {16, "TXT"}, {28, "AAAA"}, {33, "SRV"}, {257, "CAA"}
};

static uint8_t g_qry[512];
static uint8_t g_res[MAX_PKT];

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int rnd_id(uint16_t *out)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    uint8_t b[2];
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, b, 2);
    close(fd);
    if (n != 2)
        return -1;
    *out = rd16(b);
    return 0;
}

static const char *tnm(uint16_t cod)
{
    static char tmp[16];
    size_t i;
    for (i = 0; i < sizeof(TTAB) / sizeof(TTAB[0]); i++) {
        if (TTAB[i].cod == cod)
            return TTAB[i].nm;
    }
    snprintf(tmp, sizeof(tmp), "TYPE%u", (unsigned)cod);
    return tmp;
}

static int tcod(const char *str, uint16_t *out)
{
    size_t i;
    for (i = 0; i < sizeof(TTAB) / sizeof(TTAB[0]); i++) {
        if (strcasecmp(str, TTAB[i].nm) == 0) {
            *out = TTAB[i].cod;
            return 0;
        }
    }
    return -1;
}

static int lbl_ok(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static int enc_name(const char *nm, uint8_t *out, size_t cap)
{
    size_t nl = strlen(nm);
    size_t pos = 0;
    size_t i = 0;
    if (nl == 0 || nl > MAX_NAME)
        return -1;
    if (nl == 1 && nm[0] == '.') {
        if (cap < 1)
            return -1;
        out[0] = 0;
        return 1;
    }
    if (nm[nl - 1] == '.')
        nl--;
    if (nl == 0)
        return -1;
    while (i < nl) {
        size_t st = i;
        size_t ll;
        while (i < nl && nm[i] != '.') {
            if (!lbl_ok((unsigned char)nm[i]))
                return -1;
            i++;
        }
        ll = i - st;
        if (ll == 0 || ll > MAX_LBL)
            return -1;
        if (pos + 1 + ll + 1 > cap)
            return -1;
        out[pos++] = (uint8_t)ll;
        memcpy(out + pos, nm + st, ll);
        pos += ll;
        if (i < nl) {
            i++;
            if (i == nl)
                return -1;
        }
    }
    if (pos + 1 > MAX_NAME)
        return -1;
    out[pos++] = 0;
    return (int)pos;
}

static int put_ch(char *out, size_t cap, size_t *op, char c)
{
    if (*op + 1 >= cap)
        return -1;
    out[(*op)++] = c;
    return 0;
}

static int put_esc(char *out, size_t cap, size_t *op, unsigned char b, int in_name)
{
    if (b == '\\' || b == '"' || (in_name && b == '.')) {
        if (put_ch(out, cap, op, '\\') < 0 || put_ch(out, cap, op, (char)b) < 0)
            return -1;
        return 0;
    }
    if (b < 0x20 || b > 0x7e) {
        char t[5];
        size_t k;
        snprintf(t, sizeof(t), "\\%03u", (unsigned)b);
        for (k = 0; t[k]; k++) {
            if (put_ch(out, cap, op, t[k]) < 0)
                return -1;
        }
        return 0;
    }
    return put_ch(out, cap, op, (char)b);
}

static int rd_name(const uint8_t *pkt, size_t len, size_t off, char *out, size_t cap, size_t *nxt)
{
    size_t pos = off;
    size_t op = 0;
    size_t wl = 0;
    unsigned jmp = 0;
    int jumped = 0;
    for (;;) {
        uint8_t c;
        if (pos >= len)
            return -1;
        c = pkt[pos];
        if ((c & 0xc0) == 0xc0) {
            size_t tgt;
            if (pos + 1 >= len)
                return -1;
            tgt = (size_t)(((c & 0x3f) << 8) | pkt[pos + 1]);
            if (!jumped) {
                *nxt = pos + 2;
                jumped = 1;
            }
            if (tgt >= pos)
                return -1;
            if (++jmp > MAX_JMP)
                return -1;
            pos = tgt;
            continue;
        }
        if (c & 0xc0)
            return -1;
        if (c == 0) {
            if (!jumped)
                *nxt = pos + 1;
            if (op == 0 && put_ch(out, cap, &op, '.') < 0)
                return -1;
            out[op] = 0;
            return 0;
        }
        if (pos + 1 + (size_t)c > len)
            return -1;
        wl += (size_t)c + 1;
        if (wl > MAX_NAME)
            return -1;
        {
            size_t k;
            for (k = 0; k < c; k++) {
                if (put_esc(out, cap, &op, pkt[pos + 1 + k], 1) < 0)
                    return -1;
            }
            if (put_ch(out, cap, &op, '.') < 0)
                return -1;
        }
        pos += 1 + (size_t)c;
    }
}

static int bld_qry(uint8_t *buf, size_t cap, uint16_t id, const uint8_t *wn, int wl, uint16_t typ)
{
    size_t pos = 12;
    if (cap < (size_t)wl + 12 + 4 + 11)
        return -1;
    memset(buf, 0, 12);
    wr16(buf, id);
    wr16(buf + 2, 0x0100);
    wr16(buf + 4, 1);
    wr16(buf + 10, 1);
    memcpy(buf + pos, wn, (size_t)wl);
    pos += (size_t)wl;
    wr16(buf + pos, typ);
    wr16(buf + pos + 2, 1);
    pos += 4;
    buf[pos++] = 0;
    wr16(buf + pos, 41);
    wr16(buf + pos + 2, EDNS_SZ);
    memset(buf + pos + 4, 0, 6);
    pos += 10;
    return (int)pos;
}

static int chk_res(const uint8_t *q, size_t ql, const uint8_t *r, size_t rl)
{
    char qn[OUT_NAME];
    char rn[OUT_NAME];
    size_t qx;
    size_t rx;
    if (rl < 12 || ql < 12)
        return 0;
    if (rd16(q) != rd16(r))
        return 0;
    if (!(r[2] & 0x80))
        return 0;
    if (((r[2] >> 3) & 0x0f) != 0)
        return 0;
    if (rd16(r + 4) != 1)
        return 0;
    if (rd_name(q, ql, 12, qn, sizeof(qn), &qx) < 0)
        return 0;
    if (rd_name(r, rl, 12, rn, sizeof(rn), &rx) < 0)
        return 0;
    if (rx + 4 > rl || qx + 4 > ql)
        return 0;
    if (strcasecmp(qn, rn) != 0)
        return 0;
    if (rd16(r + rx) != rd16(q + qx) || rd16(r + rx + 2) != rd16(q + qx + 2))
        return 0;
    return 1;
}

static ssize_t xchg_udp(const struct sockaddr_storage *ss, socklen_t sl, const uint8_t *q, size_t ql, uint8_t *r, size_t rcap, int tmo, int rtr)
{
    int fd = socket(ss->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int att;
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)ss, sl) < 0) {
        close(fd);
        return -1;
    }
    for (att = 0; att <= rtr; att++) {
        uint64_t end;
        if (send(fd, q, ql, 0) != (ssize_t)ql) {
            close(fd);
            return -1;
        }
        end = now_ms() + (uint64_t)tmo;
        for (;;) {
            struct pollfd pf;
            int pr;
            ssize_t n;
            uint64_t cur = now_ms();
            if (cur >= end)
                break;
            pf.fd = fd;
            pf.events = POLLIN;
            pf.revents = 0;
            pr = poll(&pf, 1, (int)(end - cur));
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }
            if (pr == 0)
                break;
            n = recv(fd, r, rcap, 0);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                close(fd);
                return -1;
            }
            if (chk_res(q, ql, r, (size_t)n)) {
                close(fd);
                return n;
            }
        }
    }
    close(fd);
    errno = ETIMEDOUT;
    return -1;
}

static int wait_fd(int fd, short ev, uint64_t end)
{
    for (;;) {
        struct pollfd pf;
        int pr;
        uint64_t cur = now_ms();
        if (cur >= end) {
            errno = ETIMEDOUT;
            return -1;
        }
        pf.fd = fd;
        pf.events = ev;
        pf.revents = 0;
        pr = poll(&pf, 1, (int)(end - cur));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (pr == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        return 0;
    }
}

static int rd_full(int fd, uint8_t *buf, size_t num, uint64_t end)
{
    size_t got = 0;
    while (got < num) {
        ssize_t n;
        if (wait_fd(fd, POLLIN, end) < 0)
            return -1;
        n = recv(fd, buf + got, num - got, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int wr_full(int fd, const uint8_t *buf, size_t num, uint64_t end)
{
    size_t sent = 0;
    while (sent < num) {
        ssize_t n;
        if (wait_fd(fd, POLLOUT, end) < 0)
            return -1;
        n = send(fd, buf + sent, num - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static ssize_t xchg_tcp(const struct sockaddr_storage *ss, socklen_t sl, const uint8_t *q, size_t ql, uint8_t *r, size_t rcap, int tmo)
{
    int fd = socket(ss->ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    uint64_t end = now_ms() + (uint64_t)tmo;
    uint8_t lb[2];
    uint8_t out[2 + 512];
    size_t rl;
    int er = 0;
    socklen_t el = sizeof(er);
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)ss, sl) < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
        if (wait_fd(fd, POLLOUT, end) < 0) {
            close(fd);
            return -1;
        }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &er, &el) < 0 || er != 0) {
            close(fd);
            errno = er ? er : errno;
            return -1;
        }
    }
    if (ql > 512) {
        close(fd);
        return -1;
    }
    wr16(out, (uint16_t)ql);
    memcpy(out + 2, q, ql);
    if (wr_full(fd, out, ql + 2, end) < 0 || rd_full(fd, lb, 2, end) < 0) {
        close(fd);
        return -1;
    }
    rl = rd16(lb);
    if (rl < 12 || rl > rcap) {
        close(fd);
        errno = EPROTO;
        return -1;
    }
    if (rd_full(fd, r, rl, end) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (!chk_res(q, ql, r, rl)) {
        errno = EPROTO;
        return -1;
    }
    return (ssize_t)rl;
}

static void pr_hex(const uint8_t *p, size_t n)
{
    size_t i;
    printf("\\# %zu ", n);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static int pr_txts(const uint8_t *p, size_t n)
{
    size_t pos = 0;
    int first = 1;
    while (pos < n) {
        size_t l = p[pos++];
        char tmp[4 * 255 + 4];
        size_t op = 0;
        size_t k;
        if (pos + l > n)
            return -1;
        for (k = 0; k < l; k++) {
            if (put_esc(tmp, sizeof(tmp), &op, p[pos + k], 0) < 0)
                return -1;
        }
        tmp[op] = 0;
        printf("%s\"%s\"", first ? "" : " ", tmp);
        first = 0;
        pos += l;
    }
    return 0;
}

static int pr_rdata(const uint8_t *pkt, size_t len, size_t off, size_t rdl, uint16_t typ)
{
    char nm[OUT_NAME];
    char nm2[OUT_NAME];
    char ab[INET6_ADDRSTRLEN];
    size_t end = off + rdl;
    size_t nx;
    size_t nx2;
    if (end > len)
        return -1;
    switch (typ) {
    case 1:
        if (rdl != 4)
            return -1;
        if (!inet_ntop(AF_INET, pkt + off, ab, sizeof(ab)))
            return -1;
        printf("%s", ab);
        return 0;
    case 28:
        if (rdl != 16)
            return -1;
        if (!inet_ntop(AF_INET6, pkt + off, ab, sizeof(ab)))
            return -1;
        printf("%s", ab);
        return 0;
    case 2:
    case 5:
    case 12:
        if (rd_name(pkt, len, off, nm, sizeof(nm), &nx) < 0 || nx > end)
            return -1;
        printf("%s", nm);
        return 0;
    case 15:
        if (rdl < 3)
            return -1;
        if (rd_name(pkt, len, off + 2, nm, sizeof(nm), &nx) < 0 || nx > end)
            return -1;
        printf("%u %s", (unsigned)rd16(pkt + off), nm);
        return 0;
    case 33:
        if (rdl < 7)
            return -1;
        if (rd_name(pkt, len, off + 6, nm, sizeof(nm), &nx) < 0 || nx > end)
            return -1;
        printf("%u %u %u %s", (unsigned)rd16(pkt + off), (unsigned)rd16(pkt + off + 2), (unsigned)rd16(pkt + off + 4), nm);
        return 0;
    case 6:
        if (rd_name(pkt, len, off, nm, sizeof(nm), &nx) < 0 || nx > end)
            return -1;
        if (rd_name(pkt, len, nx, nm2, sizeof(nm2), &nx2) < 0 || nx2 + 20 > end)
            return -1;
        printf("%s %s %u %u %u %u %u", nm, nm2, (unsigned)rd32(pkt + nx2), (unsigned)rd32(pkt + nx2 + 4), (unsigned)rd32(pkt + nx2 + 8), (unsigned)rd32(pkt + nx2 + 12), (unsigned)rd32(pkt + nx2 + 16));
        return 0;
    case 16:
        return pr_txts(pkt + off, rdl);
    case 257: {
        size_t tl;
        char tg[64];
        char vl[4 * 255 + 4];
        size_t op = 0;
        size_t k;
        if (rdl < 2)
            return -1;
        tl = pkt[off + 1];
        if (2 + tl > rdl || tl >= sizeof(tg))
            return -1;
        for (k = 0; k < tl; k++)
            tg[k] = (pkt[off + 2 + k] >= 0x21 && pkt[off + 2 + k] <= 0x7e) ? (char)pkt[off + 2 + k] : '?';
        tg[tl] = 0;
        for (k = 2 + tl; k < rdl && k - 2 - tl < 255; k++) {
            if (put_esc(vl, sizeof(vl), &op, pkt[off + k], 0) < 0)
                return -1;
        }
        vl[op] = 0;
        printf("%u %s \"%s\"", (unsigned)pkt[off], tg, vl);
        return 0;
    }
    default:
        pr_hex(pkt + off, rdl);
        return 0;
    }
}

static int pr_sec(const uint8_t *pkt, size_t len, size_t *off, unsigned cnt, int quiet)
{
    unsigned i;
    for (i = 0; i < cnt; i++) {
        char nm[OUT_NAME];
        size_t nx;
        uint16_t typ;
        uint16_t cls;
        uint32_t ttl;
        size_t rdl;
        if (rd_name(pkt, len, *off, nm, sizeof(nm), &nx) < 0)
            return -1;
        if (nx + 10 > len)
            return -1;
        typ = rd16(pkt + nx);
        cls = rd16(pkt + nx + 2);
        ttl = rd32(pkt + nx + 4);
        rdl = rd16(pkt + nx + 8);
        if (nx + 10 + rdl > len)
            return -1;
        if (typ != 41) {
            if (!quiet)
                printf("%s\t%u\t%s\t%s\t", nm, (unsigned)ttl, cls == 1 ? "IN" : "CLASS?", tnm(typ));
            if (pr_rdata(pkt, len, nx + 10, rdl, typ) < 0) {
                printf("\n");
                return -1;
            }
            printf("\n");
        }
        *off = nx + 10 + rdl;
    }
    return 0;
}

static const char *rc_nm(unsigned rc)
{
    static char tmp[16];
    static const char *const tb[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    if (rc < 6)
        return tb[rc];
    snprintf(tmp, sizeof(tmp), "RCODE%u", rc);
    return tmp;
}

static int show(const uint8_t *pkt, size_t len, int quiet, int verb, int *nans)
{
    unsigned fl = rd16(pkt + 2);
    unsigned qd = rd16(pkt + 4);
    unsigned an = rd16(pkt + 6);
    unsigned ns = rd16(pkt + 8);
    unsigned ar = rd16(pkt + 10);
    size_t off = 12;
    unsigned i;
    *nans = (int)an;
    if (!quiet) {
        printf(";; status %s flags%s%s%s%s  qd %u an %u ns %u ar %u\n", rc_nm(fl & 0x0f), (fl & 0x0400) ? " aa" : "", (fl & 0x0200) ? " tc" : "", (fl & 0x0100) ? " rd" : "", (fl & 0x0080) ? " ra" : "", qd, an, ns, ar);
    }
    for (i = 0; i < qd; i++) {
        char nm[OUT_NAME];
        size_t nx;
        if (rd_name(pkt, len, off, nm, sizeof(nm), &nx) < 0 || nx + 4 > len)
            return -1;
        off = nx + 4;
    }
    if (!quiet && an)
        printf(";; ANSWER\n");
    if (pr_sec(pkt, len, &off, an, quiet) < 0)
        return -1;
    if (verb) {
        if (ns) {
            printf(";; AUTHORITY\n");
            if (pr_sec(pkt, len, &off, ns, 0) < 0)
                return -1;
        }
        if (ar) {
            printf(";; ADDITIONAL\n");
            if (pr_sec(pkt, len, &off, ar, 0) < 0)
                return -1;
        }
    }
    return 0;
}

static int p_num(const char *str, long lo, long hi, long *out)
{
    char *ep;
    long v;
    if (!str || !*str)
        return -1;
    errno = 0;
    v = strtol(str, &ep, 10);
    if (errno || *ep || v < lo || v > hi)
        return -1;
    *out = v;
    return 0;
}

static int def_srv(char *buf, size_t cap)
{
    FILE *fp = fopen("/etc/resolv.conf", "r");
    char ln[256];
    if (fp) {
        while (fgets(ln, sizeof(ln), fp)) {
            char a[64];
            char b[128];
            if (sscanf(ln, "%63s %127s", a, b) == 2 && strcmp(a, "nameserver") == 0) {
                char *pc = strchr(b, '%');
                if (pc)
                    *pc = 0;
                if (strlen(b) < cap) {
                    strcpy(buf, b);
                    fclose(fp);
                    return 0;
                }
            }
        }
        fclose(fp);
    }
    strcpy(buf, "1.1.1.1");
    return 0;
}

static int mk_addr(const char *ip, int port, struct sockaddr_storage *ss, socklen_t *sl)
{
    struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
    memset(ss, 0, sizeof(*ss));
    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port = htons((uint16_t)port);
        *sl = sizeof(*s4);
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons((uint16_t)port);
        *sl = sizeof(*s6);
        return 0;
    }
    return -1;
}

static int rev_name(const char *ip, char *out, size_t cap)
{
    uint8_t a4[4];
    uint8_t a6[16];
    if (inet_pton(AF_INET, ip, a4) == 1) {
        if (snprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa", a4[3], a4[2], a4[1], a4[0]) >= (int)cap)
            return -1;
        return 0;
    }
    if (inet_pton(AF_INET6, ip, a6) == 1) {
        size_t op = 0;
        int i;
        for (i = 15; i >= 0; i--) {
            if (op + 4 >= cap)
                return -1;
            out[op++] = "0123456789abcdef"[a6[i] & 0x0f];
            out[op++] = '.';
            out[op++] = "0123456789abcdef"[a6[i] >> 4];
            out[op++] = '.';
        }
        if (op + 9 > cap)
            return -1;
        memcpy(out + op, "ip6.arpa", 9);
        return 0;
    }
    return -1;
}

static void usage(void)
{
    fputs("usage: dnsq [options] name [type]\n"
          "  types: A NS CNAME SOA PTR MX TXT AAAA SRV CAA\n"
          "  -s IP     server address (default: first in /etc/resolv.conf)\n"
          "  -p PORT   server port 1-65535 (default 53)\n"
          "  -t MS     timeout per attempt 100-30000 (default 2000)\n"
          "  -r N      udp retries 0-5 (default 2)\n"
          "  -T        use tcp only\n"
          "  -x        reverse lookup, name is an ip address\n"
          "  -q        print rdata only\n"
          "  -v        also print authority and additional sections\n"
          "  -h        help\n"
          "exit: 0 answers, 1 no answers or dns error, 2 usage, 3 network or protocol error\n", stderr);
}

int main(int argc, char **argv)
{
    char sv[128];
    char qn[MAX_NAME + 1];
    uint8_t wn[MAX_NAME + 1];
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    long port = 53;
    long tmo = 2000;
    long rtr = 2;
    long tmp;
    int tcp = 0;
    int rev = 0;
    int quiet = 0;
    int verb = 0;
    int have_sv = 0;
    int opt;
    int wl;
    int ql;
    int nans = 0;
    uint16_t typ = 1;
    uint16_t id;
    ssize_t rl;
    const char *name;

    while ((opt = getopt(argc, argv, "s:p:t:r:Txqvh")) != -1) {
        switch (opt) {
        case 's':
            if (strlen(optarg) >= sizeof(sv)) {
                fputs("error: bad server\n", stderr);
                return 2;
            }
            strcpy(sv, optarg);
            have_sv = 1;
            break;
        case 'p':
            if (p_num(optarg, 1, 65535, &port) < 0) {
                fputs("error: bad port\n", stderr);
                return 2;
            }
            break;
        case 't':
            if (p_num(optarg, 100, 30000, &tmp) < 0) {
                fputs("error: bad timeout\n", stderr);
                return 2;
            }
            tmo = tmp;
            break;
        case 'r':
            if (p_num(optarg, 0, 5, &tmp) < 0) {
                fputs("error: bad retries\n", stderr);
                return 2;
            }
            rtr = tmp;
            break;
        case 'T':
            tcp = 1;
            break;
        case 'x':
            rev = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'v':
            verb = 1;
            break;
        case 'h':
            usage();
            return 0;
        default:
            usage();
            return 2;
        }
    }
    if (optind >= argc || argc - optind > 2) {
        usage();
        return 2;
    }
    name = argv[optind];
    if (rev) {
        typ = 12;
        if (rev_name(name, qn, sizeof(qn)) < 0) {
            fputs("error: bad ip address\n", stderr);
            return 2;
        }
        name = qn;
    }
    if (argc - optind == 2) {
        if (tcod(argv[optind + 1], &typ) < 0) {
            fputs("error: unsupported type\n", stderr);
            return 2;
        }
    }
    if (!have_sv)
        def_srv(sv, sizeof(sv));
    if (mk_addr(sv, (int)port, &ss, &sl) < 0) {
        fputs("error: server must be an ip address\n", stderr);
        return 2;
    }
    wl = enc_name(name, wn, sizeof(wn));
    if (wl < 0) {
        fputs("error: bad name\n", stderr);
        return 2;
    }
    if (rnd_id(&id) < 0) {
        fputs("error: no random source\n", stderr);
        return 3;
    }
    ql = bld_qry(g_qry, sizeof(g_qry), id, wn, wl, typ);
    if (ql < 0) {
        fputs("error: bad name\n", stderr);
        return 2;
    }
    {
        uint64_t t0 = now_ms();
        const char *pr = tcp ? "tcp" : "udp";
        if (tcp) {
            rl = xchg_tcp(&ss, sl, g_qry, (size_t)ql, g_res, sizeof(g_res), (int)tmo);
        } else {
            rl = xchg_udp(&ss, sl, g_qry, (size_t)ql, g_res, sizeof(g_res), (int)tmo, (int)rtr);
            if (rl >= 12 && (g_res[2] & 0x02)) {
                pr = "tcp";
                rl = xchg_tcp(&ss, sl, g_qry, (size_t)ql, g_res, sizeof(g_res), (int)tmo);
            }
        }
        if (rl < 0) {
            fprintf(stderr, "error: %s query failed: %s\n", pr, strerror(errno));
            return 3;
        }
        if (!quiet)
            printf(";; server %s port %ld via %s rtt %llu ms size %zd\n", sv, port, pr, (unsigned long long)(now_ms() - t0), rl);
    }
    if (show(g_res, (size_t)rl, quiet, verb, &nans) < 0) {
        fputs("error: malformed response\n", stderr);
        return 3;
    }
    if ((rd16(g_res + 2) & 0x0f) != 0 || nans == 0)
        return 1;
    return 0;
}
