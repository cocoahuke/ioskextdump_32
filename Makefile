CC=clang
CFLAGS=-fobjc-arc -fobjc-link-runtime -framework Foundation src/libcapstone.a

build/ioskextdump_32:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.m -o $@

.PHONY:install
install:build/ioskextdump_32
	mkdir -p /usr/local/bin
	cp build/ioskextdump_32 /usr/local/bin/ioskextdump_32

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/ioskextdump_32

.PHONY:clean
clean:
	rm -rf build
