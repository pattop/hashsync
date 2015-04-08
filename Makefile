all: update_sha1s compare_sha1s

update_sha1s: sha1.c sha1-fast-64.S sha1.h update_sha1s.C
	g++ -std=gnu++11 -Wall -flto -fuse-linker-plugin -O2 -o $@ $^

compare_sha1s: compare_sha1s.C
	g++ -std=gnu++11 -Wall -flto -fuse-linker-plugin -O2 -o $@ $^
