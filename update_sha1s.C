#include <string>
#include <unordered_map>

#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "sha1.h"

/*
 * Management of a ".sha1s" file containing file hashes of
 * files in the directory tree.
 *
 * File format:
 *   filename<NULL>modified<NULL>sha1<NULL><NULL>
 *
 * Algorithm:
 *   1. Load existing .sha1s
 *   2. Enumerate directory, for each file
 *     2a. If filename & modified match existing do nothing
 *     2b. If filename matches but not modified, update entry
 *     2c. If filename doesn't match create new entry
 *     2d. If removing missing files mark each file as touched
 *   3. If removing files, remove all untouched files
 *   4. Write new .sha1s
 */

class CFileHash {
public:
	CFileHash()
	: st_mtim_{0, 0}
	, touched{false}
	{ }

	CFileHash(const std::string &hash, const struct timespec &st_mtim)
	: hash_(hash)
	, st_mtim_(st_mtim)
	, touched{false}
	{ }

private:
	std::string hash_; /* sha1 hash */
	struct timespec st_mtim_; /* last modification time */
	bool touched;
};

typedef std::unordered_map<std::string, CFileHash> CFileHashMap;

void usage(const char *name)
{
	const char *usage =
	    "Usage: %s [options]\n"
	    "Options:\n"
	    "  -c remove SHA1 hashes for missing files\n";
	fprintf(stderr, usage, name);
	exit(EXIT_FAILURE);
}

std::string get_string(const char *&it, const char *buf, const size_t size)
{
	if (it >= (buf + size)) {
		fprintf(stderr, "sha1s truncated?\n");
		exit(EXIT_FAILURE);
	}
	std::string tmp(it);
	it += tmp.size() + 1;

	return tmp;
}

CFileHashMap load_sha1s()
{
	CFileHashMap tmp;

	/* load existing SHA1 hashes */
	const int fd = open(".sha1s", O_RDONLY);
	if (fd < 0 && errno != ENOENT) {
		perror("Failed to open .sha1s");
		exit(EXIT_FAILURE);
	}

	if (fd < 0) {
		printf("No existing .sha1s file\n");
		return tmp;
	}

	const off_t size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
		perror("SEEK_END failed");
		exit(EXIT_FAILURE);
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		perror("SEEK_SET failed");
		exit(EXIT_FAILURE);
	}

	char *buf = (char*)malloc(size + 1);
	if (read(fd, buf, size) != size) {
		perror("read failed");
		exit(EXIT_FAILURE);
	}
	buf[size] = 0;

	if (close(fd) != 0) {
		perror("close failed");
		exit(EXIT_FAILURE);
	}

	const char *it = buf;
	while (buf - it > 1) {
		std::string fname(get_string(it, buf, size));
		std::string time(get_string(it, buf, size));
		std::string hash(get_string(it, buf, size));

		char *pend;
		long long sec = strtoll(time.c_str(), &pend, 10);
		long nsec = strtol(pend, &pend, 10);

		tmp[fname] = CFileHash(hash, (struct timespec){sec, nsec});
	}

	return tmp;
}

void update_sha1(CFileHashMap &sha1s, const std::string &path)
{
//	sha1s[path]


}

void update_sha1s(CFileHashMap &sha1s, std::string path = ".")
{
	DIR* d = opendir(path.c_str());
	if (!d) {
		perror("Failed to open directory");
		exit(EXIT_FAILURE);
	}

	struct dirent* de;
	while ((de = readdir(d))) {
		std::string name{path + "/" + de->d_name};
		if (de->d_type == DT_DIR) {
			if (strcmp(de->d_name, ".") == 0)
				continue;
			if (strcmp(de->d_name, "..") == 0)
				continue;
			update_sha1s(sha1s, name);
			continue;
		}
		if (de->d_type != DT_REG) {
			printf("Skipping %s -- not a regular file\n", name.c_str());
			continue;
		}
		update_sha1(sha1s, name.c_str());
	}

	if (closedir(d) < 0) {
		perror("Failed to close directory");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	bool remove = false;

	int opt;
	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c':
			remove = true;
		default:
			usage(argv[0]);
		}
	}

	CFileHashMap sha1s{load_sha1s()};
	update_sha1s(sha1s);


	return EXIT_SUCCESS;
}
