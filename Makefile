CFLAGS := -O2 -ggdb -Wall -Wno-pointer-sign -Wno-unused-label -Wno-unused-function -Wno-unused-but-set-variable

erigon_extract: erigon_extract.c
	$(CC) -Ilibmdbx -std=gnu11 -pthread $(CFLAGS) -o $@ $< -Llibmdbx libmdbx/libmdbx.a
