.PHONY: test clean

test: test-kcbc
	./test-kcbc

test-ciphers: test-kcbc.c
	$(CC) test-kcbc.c -o $@

clean:
	rm -f test-kcbc
