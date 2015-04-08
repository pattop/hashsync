#include <cassert>
#include <string>
#include <unordered_map>

#include <dirent.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha1.h"

/*
 * Management of a ".sha1s" file containing file hashes of
 * files in the directory tree.
 *
 * File format:
 *   filename<NULL>modified_sec.modified_nsec<NULL>sha1<NULL><NULL>
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
	, touched_{false}
	{ }

	CFileHash(const std::string &hash, const struct timespec &st_mtim, bool touched = false)
	: hash_(hash)
	, st_mtim_(st_mtim)
	, touched_(touched)
	{ }

	void touch() { touched_ = true; }
	bool touched() const { return touched_; }
	const struct timespec& modified() const { return st_mtim_; }
	const std::string& hash() const { return hash_; }

private:
	std::string hash_; /* sha1 hash */
	struct timespec st_mtim_; /* last modification time */
	bool touched_;
};

bool operator==(const struct timespec &lhs, const struct timespec &rhs)
{
	return (lhs.tv_sec == rhs.tv_sec) && (lhs.tv_nsec == rhs.tv_nsec);
}

typedef std::unordered_map<std::string, CFileHash> CFileHashMap;

void usage(const char *name)
{
	const char *usage =
	    "Usage: %s [options]\n"
	    "Options:\n"
	    "  -c remove SHA1 hashes for missing files\n"
	    "  -i <days> ignore files modified longer than <days> in the past\n";
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
	if (fd < 0 && errno != ENOENT)
		error(EXIT_FAILURE, errno, "Failed to open .sha1s");

	if (fd < 0) {
		printf("No existing .sha1s file\n");
		return tmp;
	}

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

		char *end;
		long sec = strtol(time.c_str(), &end, 10);
		if (*end != '.')
			error(EXIT_FAILURE, EINVAL, "parse error, expected '.'");
		++end;
		long nsec = strtol(end, &end, 10);
		if (*end != 0)
			error(EXIT_FAILURE, EINVAL, "parse error, expected NULL");

		if (*it != 0)
			error(EXIT_FAILURE, EINVAL, "parse error, expected NULL");
		++it;

		tmp[fname] = CFileHash(hash, (struct timespec){sec, nsec});
	}

	return tmp;
}

char sha1_buf[1024 * 1024];
std::string calculate_sha1(int fd)
{
	sha1_state s;
	sha1_start(&s);

	ssize_t rd;
	while ((rd = read(fd, sha1_buf, sizeof(sha1_buf))) > 0)
		sha1_process(&s, sha1_buf, rd);

	if (rd < 0)
		error(EXIT_FAILURE, errno, "read");

	uint32_t hash[5];
	sha1_finish(&s, hash);

	char hashstr[41];
	snprintf(hashstr, sizeof(hashstr), "%08x%08x%08x%08x%08x",
	    hash[0], hash[1], hash[2], hash[3], hash[4]);
	return hashstr;
}

bool update_sha1(CFileHashMap &sha1s, const std::string &path)
{
	const int fd = open(path.c_str(), O_RDONLY);
	if (fd < 0 && errno != ENOENT)
		error(EXIT_FAILURE, errno, "Failed to open %s", path.c_str());

	struct stat sb;
	if (fstat(fd, &sb) != 0)
		error(EXIT_FAILURE, errno, "Could not stat %s", path.c_str());

	auto it = sha1s.find(path);
	if ((it != sha1s.end()) && (it->second.modified() == sb.st_mtim)) {
		it->second.touch();
		//printf("match %s\n", path.c_str());
		return false;
	}

	printf("%s %s\n", it == sha1s.end() ? "add" : "mod", path.c_str());
	sha1s[path] = CFileHash(calculate_sha1(fd), sb.st_mtim, true);

	if (close(fd) != 0)
		error(EXIT_FAILURE, errno, "close");

	return true;
}

bool update_sha1s(CFileHashMap &sha1s, std::string path = ".")
{
	DIR* d = opendir(path.c_str());
	if (!d)
		error(EXIT_FAILURE, errno, "Failed to open directory");

	bool updated = false;
	struct dirent* de;
	while ((de = readdir(d))) {
		std::string name{path + "/" + de->d_name};
		if (name == "./.sha1s")
			continue;
		if (name == "./.sha1s.tmp")
			continue;
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
		updated = update_sha1(sha1s, name.c_str()) || updated;
	}

	if (closedir(d) < 0)
		error(EXIT_FAILURE, errno, "Failed to close directory");

	return updated;
}

void parse_long_arg(long &arg, const char *s)
{
	errno = 0;
	char* p;
	arg = strtoul(s, &p, 0);
	if (errno != 0)
		error(EXIT_FAILURE, errno, "%s", s);
	if (s == p)
		error(EXIT_FAILURE, EINVAL, "%s", s);
	if (*p)
		error(EXIT_FAILURE, EINVAL, "%s", s);
}

int main(int argc, char *argv[])
{
	bool remove_missing = false;
	long ignore_seconds = 0;

	int opt;
	while ((opt = getopt(argc, argv, "ci:")) != -1) {
		switch (opt) {
		case 'c':
			remove_missing = true;
			break;
		case 'i':
			parse_long_arg(ignore_seconds, optarg);
			if (ignore_seconds > (0xFFFFFFFF / 86400))
				error(EXIT_FAILURE, EINVAL, "%s too big", optarg);
			ignore_seconds *= 86400;
			break;
		default:
			usage(argv[0]);
		}
	}

	bool need_to_write = false;

	CFileHashMap sha1s{load_sha1s()};
	if (!update_sha1s(sha1s))
		printf("No new or modified files.\n");
	else
		need_to_write = true;

	struct timespec now;
	if (clock_gettime(CLOCK_REALTIME, &now) != 0)
		error(EXIT_FAILURE, errno, "gettimeofday");

	if (remove_missing || ignore_seconds) {
		bool expired = false;
		bool missing = false;
		for (auto it = begin(sha1s); it != end(sha1s);) {
			bool r = false;
			if (remove_missing && !it->second.touched()) {
				printf("rem %s\n", it->first.c_str());
				r = true;
				missing = true;
			}
			else if (ignore_seconds && (now.tv_sec - it->second.modified().tv_sec) > ignore_seconds) {
				printf("exp %s\n", it->first.c_str());
				r = true;
				expired = true;
			}
			if (r) {
				it = sha1s.erase(it);
				need_to_write = true;
			}
			else
				++it;
		}

		if (remove_missing && !missing)
			printf("No missing files.\n");
		if (ignore_seconds && !expired)
			printf("No expired files.\n");
	}

	if (!need_to_write)
		return EXIT_SUCCESS;

	FILE *f = fopen(".sha1s.tmp", "wb");
	if (!f)
		error(EXIT_FAILURE, errno, "failed to open .sha1s.tmp");

	for (const auto &h : sha1s) {
		if (remove_missing && !h.second.touched())
			continue;
		char null[2] = {0};
		char modified[128];
		size_t modified_sz = snprintf(modified, 128, "%ld.%ld",
		    h.second.modified().tv_sec, h.second.modified().tv_nsec);
		if ((fwrite(h.first.c_str(), h.first.size(), 1, f) < 0) ||
		    (fwrite(null, 1, 1, f) < 0) ||
		    (fwrite(modified, modified_sz, 1, f) < 0) ||
		    (fwrite(null, 1, 1, f) < 0) ||
		    (fwrite(h.second.hash().c_str(), h.second.hash().size(), 1, f) < 0) ||
		    (fwrite(null, 2, 1, f) < 0))
			error(EXIT_FAILURE, errno, "fwrite");
	}

	if (fclose(f) != 0)
		error(EXIT_FAILURE, errno, "fclose");

	if (rename(".sha1s.tmp", ".sha1s") != 0)
		error(EXIT_FAILURE, errno, "rename");

	return EXIT_SUCCESS;
}
