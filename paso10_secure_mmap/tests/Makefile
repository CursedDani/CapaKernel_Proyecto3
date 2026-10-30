# Pruebas de ataque/defensa (espacio de usuario). -Werror: clean build.
CC     ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -pthread

PROGS = test_authorized test_unauthorized test_fd_inherit test_prot_exec \
        test_private_map test_oob_pgoff test_ro_write test_race_madvise \
        test_crypto_rest test_tamper attack_matrix

all: $(PROGS)

%: %.c test_common.h ../secure_vault_uapi.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGS)

.PHONY: all clean
