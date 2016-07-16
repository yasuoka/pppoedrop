/*
 * Copyright (c) 2016 YASUOKA Masahiko <yasuoka@yasuoka.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethertypes.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sysexits.h>
#include <stdarg.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#ifndef nitems
#define	nitems(_x)	(sizeof((_x)) / sizeof((_x)[0]))
#endif

struct bpf_insn insns[] = {
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_PPPOEDISC, 2, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_PPPOE, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, (u_int)0),
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
};

#define PPPOE_RFC2516_TYPE      0x01
#define PPPOE_RFC2516_VER       0x01
#define PPPOE_CODE_PADT         0xa7

struct pppoe_header {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t ver:4, type:4;
#else
	uint8_t type:4, ver:4;
#endif
	uint8_t code;
	uint16_t session_id;
	uint16_t length;
} __attribute__((__packed__));

struct bpf_program bf_filter = {
	.bf_len = nitems(insns),
	.bf_insns = insns
};

void	 hd(FILE *, const u_char *, int);
void	 usage(void);
void	 slog(const char *, ...);

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s ifname\n", __progname);
}

int
main(int argc, char *argv[])
{
	int		 i, ival, ch, bpf = -1;
	const char	*ifname = NULL;
	u_char		*pkt, bhost[ETHER_ADDR_LEN], rpkt[60];
	char		 path[PATH_MAX], buf[2048];
	struct ifreq	 ifr;
	ssize_t		 sz;
	struct pollfd	 pfd[1];
	struct bpf_hdr	*bhdr;
	struct ether_header
			*ehdr;
	struct pppoe_header
			*phdr;
		 
	while ((ch = getopt(argc, argv, "")) != -1)
		switch (ch) {
		default:
			usage();
			exit(EX_USAGE);
		}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage();
		exit(EX_USAGE);
	}

	ifname = *(argv++);

	for (i = 0; ; i++) {
		snprintf(path, sizeof(path), "/dev/bpf%d", i);
		if ((bpf = open(path, O_RDWR)) >= 0)
			break;
		if (errno == EBUSY)
			continue;
		err(EX_OSERR, "open(%s)", path);
	}
	if (bpf < 0)
		err(EX_OSERR, "open(%s)", path);

	slog("Opened %s", path);

	ival = 2048;
	if (ioctl(bpf, BIOCSBLEN, &ival) != 0)
		err(EX_OSERR, "ioctl(,BIOCSBLEN)");

	ival = 1;
	if (ioctl(bpf, BIOCIMMEDIATE, &ival) != 0)
		err(EX_OSERR, "ioctl(,BIOCIMMEDIATE)");

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(bpf, BIOCSETIF, &ifr) != 0)
		err(EX_OSERR, "ioctl(,BIOCSETIF,%s)", ifname);

        if (ioctl(bpf, BIOCSETF, &bf_filter) != 0)
		err(EX_OSERR, "ioctl(,BIOCSETF)");


	pfd[0].fd = bpf;
	pfd[0].events = POLLIN;
	while (poll(pfd, 1, 0) == 0) {
		sz = read(bpf, buf, sizeof(buf));
		if (sz <= 0)
			err(EX_OSERR, "read %d", sz);
		pkt = buf;
		while (sz > 0) {
			if (sz < sizeof(*bhdr))
				errx(1, "received data is too small");
			bhdr = (struct bpf_hdr *)pkt;
			if (sz < bhdr->bh_hdrlen + sizeof(*ehdr))
				errx(1, "received data is too small");
			ehdr = (struct ether_header *)(pkt + bhdr->bh_hdrlen);
			if (ntohs(ehdr->ether_type) == ETHERTYPE_PPPOE) {
				if (sz < bhdr->bh_hdrlen + sizeof(*ehdr) +
				    sizeof(*bhdr))
					errx(1, "received pppoe packet is "
					    "too small");

				phdr = (struct pppoe_header *)(ehdr + 1);
				if (phdr->type != PPPOE_RFC2516_TYPE ||
				    phdr->ver != PPPOE_RFC2516_VER)
					err(1, "received pppoe packet is"
					    "has wrong header");
				slog("Recieved code=%02x session-id=%d, "
				    "length=%d", phdr->code,
				    ntohs(phdr->session_id),
				    ntohs(phdr->length));

				memset(rpkt, 0, sizeof(rpkt));
				memcpy(rpkt, (u_char *)ehdr,
				    sizeof(*ehdr) + sizeof(*phdr));
				ehdr = (struct ether_header *)rpkt;
				phdr = (struct pppoe_header *)(ehdr + 1);
				memcpy(bhost, ehdr->ether_dhost,
				    ETHER_ADDR_LEN);
				memcpy(ehdr->ether_dhost, ehdr->ether_shost,
				    ETHER_ADDR_LEN);
				memcpy(ehdr->ether_shost, bhost,
				    ETHER_ADDR_LEN);
				ehdr->ether_type = htons(ETHERTYPE_PPPOEDISC);
				phdr->code = PPPOE_CODE_PADT;
				phdr->length = htons(sizeof(*phdr) + 8);
				slog("Sending code=%02x session-id=%d, "
				    "length=%d", phdr->code,
				    ntohs(phdr->session_id),
				    ntohs(phdr->length));
				hd(stderr, rpkt, sizeof(rpkt));
				write(bpf, rpkt, sizeof(rpkt));
				goto done;
			}
			pkt = pkt + BPF_WORDALIGN(bhdr->bh_hdrlen +
			    bhdr->bh_caplen);
			sz -= BPF_WORDALIGN(bhdr->bh_hdrlen + bhdr->bh_caplen);
		}
	}
done:

	close(bpf);


	exit(0);
}

void
slog(const char *fmt, ...)
{
	va_list		 ap;
	int		 off;
	char		 buf[BUFSIZ];
	time_t		 currtime;
	struct tm	 currtm;

	time(&currtime);
	localtime_r(&currtime, &currtm);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S ", &currtm);
	off = strlen(buf);

	va_start(ap, fmt);
	vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
	strlcat(buf, "\n", sizeof(buf));
	fputs(buf, stderr);
	va_end(ap);
}

void
hd(FILE *file, const u_char *buf, int len)
{
        int i, o = 0;
        int hd_cnt = 0;
        char linebuf[80];
        char asciibuf[17];

        memset(asciibuf, ' ', sizeof(asciibuf));
        asciibuf[sizeof(asciibuf)-1] = '\0';

        for (i = 0; i < len; i++) {
                if (0x20 <= *(buf+i)  && *(buf+i) <= 0x7e)
                        asciibuf[hd_cnt % 16] = *(buf+i);
                else
                        asciibuf[hd_cnt % 16] = '.';

                switch (hd_cnt % 16) {
                case 0:
                        o += snprintf(linebuf + o, sizeof(linebuf) - o,
                            "%04x  %02x", hd_cnt,
                            (unsigned char)*(buf+i));
                        break;
                case 15:
                        o += snprintf(linebuf + o, sizeof(linebuf) - o,
                            "%02x", (unsigned char)*(buf+i));
                        fprintf(file, "\t%-47s  |%s|\n", linebuf, asciibuf);
                        memset(asciibuf, ' ', sizeof(asciibuf));
                        asciibuf[sizeof(asciibuf)-1] = '\0';
                        o = 0;
                        break;
                case 8:
                        o += snprintf(linebuf + o, sizeof(linebuf) - o,
                            "- %02x", (unsigned char)*(buf+i));
                        break;
                default:
                        if (hd_cnt % 2 == 1)
                                o += snprintf(linebuf + o, sizeof(linebuf) - o,
                                    "%02x ", (unsigned char)*(buf+i));
                        else
                                o += snprintf(linebuf + o, sizeof(linebuf) - o,
                                    "%02x", (unsigned char)*(buf+i));
                        break;
                }
                hd_cnt++;
        }
        if (hd_cnt > 0 && (hd_cnt % 16) != 0)
                fprintf(file, "\t%-47s  |%s|\n", linebuf, asciibuf);
        fflush(file);
}
