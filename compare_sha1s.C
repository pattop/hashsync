#include <cassert>
#include <string>
#include <unordered_map>

#include <dirent.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Compare two sha1s files.
 *
 * Print a list of files which need to be synchronised.
 *
 * File format:
 *   filename<NULL>modified_sec.modified_nsec<NULL>sha1<NULL>\n
 *
 * Algorithm:
 *   1. Load sha1s_local
 *   2. Load sha1s_remote
 *   3. For each sha1 in remote
 *     3a. If sha1 is not in sha1s_local print remote file name
 */

typedef std::unordered_map<std::string, std::string> CFileHashMap;

void usage(const char *name)
{
	const char *usage =
	    "Usage: %s <local.sha1s> <remote.sha1s>\n";
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

CFileHashMap load_sha1s(const char *file)
{
	CFileHashMap tmp;

	const int fd = open(file, O_RDONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "Failed to open %s", file);

	const off_t size = lseek(fd, 0, SEEK_END);
	if (size < 0)
		error(EXIT_FAILURE, errno, "SEEK_END");

	if (lseek(fd, 0, SEEK_SET) != 0)
		error(EXIT_FAILURE, errno, "SEE_SET");

	char *buf = (char*)malloc(size + 1);
	if (!buf)
		error(EXIT_FAILURE, errno, "malloc");

	ssize_t rd = read(fd, buf, size);
	if (rd < 0)
		error(EXIT_FAILURE, errno, "read");
	if (rd != size) {
		fprintf(stderr, "short read?\n");
		exit(EXIT_FAILURE);
	}

	buf[size] = 0;

	if (close(fd) != 0)
		error(EXIT_FAILURE, errno, "close");

	const char *it = buf;
	while ((buf + size) - it > 1) {
		std::string fname(get_string(it, buf, size));
		std::string time(get_string(it, buf, size));
		std::string hash(get_string(it, buf, size));

		if (*it != 0 && *it != '\n')
			error(EXIT_FAILURE, EINVAL, "parse error, expected NULL or newline");
		++it;

		tmp[hash] = fname;
	}

	free(buf);
	return tmp;
}

void compare_sha1s(const CFileHashMap &m, const char *file)
{
	const int fd = open(file, O_RDONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "Failed to open %s", file);

	const off_t size = lseek(fd, 0, SEEK_END);
	if (size < 0)
		error(EXIT_FAILURE, errno, "SEEK_END");

	if (lseek(fd, 0, SEEK_SET) != 0)
		error(EXIT_FAILURE, errno, "SEE_SET");

	char *buf = (char*)malloc(size + 1);
	if (!buf)
		error(EXIT_FAILURE, errno, "malloc");

	ssize_t rd = read(fd, buf, size);
	if (rd < 0)
		error(EXIT_FAILURE, errno, "read");
	if (rd != size) {
		fprintf(stderr, "short read?\n");
		exit(EXIT_FAILURE);
	}

	buf[size] = 0;

	if (close(fd) != 0)
		error(EXIT_FAILURE, errno, "close");

	const char *it = buf;
	while ((buf + size) - it > 1) {
		std::string fname(get_string(it, buf, size));
		std::string time(get_string(it, buf, size));
		std::string hash(get_string(it, buf, size));

		if (*it != 0 && *it != '\n')
			error(EXIT_FAILURE, EINVAL, "parse error, expected NULL or newline");
		++it;

		if (m.find(hash) == m.end())
			printf("%s\n", fname.c_str());
	}

	free(buf);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		usage(argv[0]);

	const char *local = argv[1];
	const char *remote = argv[2];

	CFileHashMap local_sha1s(load_sha1s(local));
	compare_sha1s(local_sha1s, remote);

	return EXIT_SUCCESS;
}
