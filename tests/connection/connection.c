#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

static int connection(const char *alg_name) {
    struct sockaddr_alg sa = {
            .salg_family = AF_ALG,
            .salg_type = "skcipher",
    };
}

int main() {

}