#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

static uint8_t test_key[32] = {
	0xe9, 0xde, 0xe7, 0x2c, 0x8f, 0x0c, 0x0f, 0xa6,
	0x2d, 0xdb, 0x49, 0xf4, 0x6f, 0x73, 0x96, 0x47,
	0x06, 0x07, 0x53, 0x16, 0xed, 0x24, 0x7a, 0x37,
	0x39, 0xcb, 0xa3, 0x83, 0x03, 0xa9, 0x8b, 0xf6
};

static uint8_t test_pt[48] = {
	0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
	0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	0x85, 0x04, 0xfa, 0x9d, 0x1b, 0xb6, 0xc7, 0xac,
	0x25, 0x2e, 0x72, 0xc2, 0x02, 0xfd, 0xce, 0x0d,
	0x5b, 0xe3, 0xd6, 0x12, 0x17, 0xb9, 0x61, 0x81,
	0xfe, 0x67, 0x86, 0xad, 0x71, 0x6b, 0x89, 0x0b
};

static uint8_t out1[] = {
	0x72, 0x60, 0xda, 0x60, 0x13, 0x8f, 0x96, 0xc9,
};

static uint8_t out2[] = {
	0x2D, 0xAB, 0x59, 0x77, 0x1B, 0x4B, 0x16, 0xD0,
};

#ifndef AF_ALG
	#define AF_ALG 38
#endif
#ifndef SOL_ALG
	#define SOL_ALG 279
#endif

static int hash_sd(int sd, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	ssize_t len;
	do
	{
		len = send(sd, in, inlen, out ? 0 : MSG_MORE);
		if (len == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			fprintf(stdout, "writing to AF_ALG hasher failed: %s", strerror(errno));
			return 1;
		}
		in += len;
		inlen -= len;
	}
	while (inlen);

	if (out)
	{
		while (outlen)
		{
			len = read(sd, out, outlen);
			if (len == -1)
			{
				if (errno == EINTR)
				{
					continue;
				}
				fprintf(stdout, "reading AF_ALG hasher failed: %s", strerror(errno));
				return 1;
			}
			outlen -= len;
			out += len;
		}
	}
	return 0;
}

static int hash(int sd, uint8_t *in, size_t inlen, 
				uint8_t *out, size_t outlen, uint8_t *expected)
{
	int i, ret;

	if ((ret = hash_sd(sd, in, inlen, out, outlen)) != 0)
		return ret;

	for (i = 0; i < outlen; i++)
	{
		if (out[i] != expected[i])
			return -2;
	}
	
	return 0;
}

static int test_bmac(uint8_t *in, size_t inlen, uint8_t *expected)
{
	const char *algname = "kcbc(belt)";
	
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type   = "hash",
	};
	char error[128] = {};
		
	int sd[2] = {-1, -1};
	int ret = -1;

	uint8_t out[8] = {};
	size_t outlen = 8;

	strncpy(sa.salg_name, algname, sizeof(sa.salg_name));
	
	fprintf(stdout, "testing %s...", algname);
	fflush(stdout);

	if ((sd[0] = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
	{
		snprintf(error, sizeof(error),
				"opening AF_ALG socket failed: %s", strerror(errno));
		goto out;
	}

	if (bind(sd[0], (struct sockaddr *) &sa, sizeof(sa)) != 0)
	{
		snprintf(error, sizeof(error), 
				"binding AF_ALG socket for '%s' failed: %s", sa.salg_name, 
				strerror(errno));
		goto close_sd0;
	}
	
	/* Set key */
	setsockopt(sd[0], SOL_ALG, ALG_SET_KEY, test_key, sizeof(test_key));
	if ((sd[1] = accept(sd[0], NULL, 0)) == -1)
	{
		snprintf(error, sizeof(error),
				"setting AF_ALG key failed: %s", strerror(errno));
		goto close_sd0;
	}

	/* Test hash */
	if ((ret = hash(sd[1], in, inlen, out, outlen, expected)) != 0)
	{
		snprintf(error, sizeof(error),
				"using hash is incorrect");
		goto close_sd1;
	}

close_sd1:
	close(sd[1]);
close_sd0:
	close(sd[0]);
out:
	fprintf(stdout, (ret == 0)
		? "ok\n" : "\x1b[31mfailed\x1b[0m");
	
	ret != 0 ? fprintf(stdout, "\n%s", error) : fprintf(stdout, ""); 	
	return ret;
}

int main(int argc, const char *argv)
{
	int ret = 0;
	
	if ((ret = test_bmac(test_pt, 13, out1)) != 0)
		goto out;
		
	if ((ret = test_bmac(test_pt, 48, out2)) != 0)
		goto out;

out:
	fprintf(stdout, (ret == 0)
		? "\n\x1b[32mAll tests have passed.\x1b[0m\n"
		: "\n\x1b[31mThere are failures!\x1b[0m\n");

	return ret;
}
