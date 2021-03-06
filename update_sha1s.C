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

long ignore_seconds = 0;
struct timespec now;
const char *filename = ".sha1s";

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
	    "  -i <days> ignore files modified longer than <days> in the past\n"
	    "  -f <filename> use filename instead of default .sha1s\n";
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
	const int fd = open(filename, O_RDONLY);
	if (fd < 0 && errno != ENOENT)
		error(EXIT_FAILURE, errno, "Failed to open %s", filename);

	if (fd < 0) {
		printf("No existing sha1s file %s\n", filename);
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

		if (*it != 0 && *it != '\n')
			error(EXIT_FAILURE, EINVAL, "parse error, expected NULL or newline");
		++it;

		tmp[fname] = CFileHash(hash, (struct timespec){sec, nsec});
	}

	free(buf);
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

	if (ignore_seconds && (now.tv_sec - sb.st_mtim.tv_sec) > ignore_seconds) {
		if (close(fd) != 0)
			error(EXIT_FAILURE, errno, "close");
		return false;
	}

	auto it = sha1s.find(path);
	if ((it != sha1s.end()) && (it->second.modified() == sb.st_mtim)) {
		it->second.touch();
		//printf("match %s\n", path.c_str());
		if (close(fd) != 0)
			error(EXIT_FAILURE, errno, "close");
		return false;
	}

	/*
	 * Ignore files modified less than 3 seconds ago.
	 * Something funny seems to be happening with very fresh files
	 * on CentOS 6.6.
	 */
	struct timespec nownow;
	if (clock_gettime(CLOCK_REALTIME, &nownow) != 0)
		error(EXIT_FAILURE, errno, "clock_gettime");
	if ((nownow.tv_sec - sb.st_mtim.tv_sec) < 3)
		printf("<3s %s\n", path.c_str());
	else {
		printf("%s %s\n", it == sha1s.end() ? "add" : "mod", path.c_str());
		sha1s[path] = CFileHash(calculate_sha1(fd), sb.st_mtim, true);
	}

	if (close(fd) != 0)
		error(EXIT_FAILURE, errno, "close");

	return true;
}

bool update_sha1s(CFileHashMap &sha1s, std::string path = ".")
{
	DIR* d = opendir(path.c_str());
	if (!d)
		error(EXIT_FAILURE, errno, "Failed to open directory %s", path.c_str());

	bool updated = false;
	struct dirent* de;
	while ((de = readdir(d))) {
		std::string name(path + "/" + de->d_name);
		/* Ignore anything starting with ".sha1s" */
		if (strncmp(name.c_str(), "./.sha1s", 8) == 0)
			continue;
		if (de->d_type == DT_LNK) {
			char lnk[PATH_MAX + 1];
			int r = readlink(name.c_str(), lnk, sizeof(lnk));
			if (r < 0)
				error(EXIT_FAILURE, errno, "Failed to read link");
			if (r > PATH_MAX)
				error(EXIT_FAILURE, EIO, "Link size too big");
			lnk[r] = '\0';
			struct stat sb;
			if (stat(lnk, &sb) != 0)
				error(EXIT_FAILURE, errno, "Could not stat %s", lnk);
			switch (sb.st_mode & S_IFMT) {
			case S_IFDIR:
				de->d_type = DT_DIR;
				break;
			case S_IFREG:
				de->d_type = DT_REG;
				break;
			default:
				printf("Skipping %s -- link to something unusual?\n", name.c_str());
				continue;
			}
		}
		if (de->d_type == DT_DIR) {
			if (strcmp(de->d_name, ".") == 0)
				continue;
			if (strcmp(de->d_name, "..") == 0)
				continue;
			updated = update_sha1s(sha1s, name) || updated;
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

	int opt;
	while ((opt = getopt(argc, argv, "ci:f:")) != -1) {
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
		case 'f':
			filename = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (clock_gettime(CLOCK_REALTIME, &now) != 0)
		error(EXIT_FAILURE, errno, "clock_gettime");

	bool need_to_write = false;

	CFileHashMap sha1s(load_sha1s());
	if (!update_sha1s(sha1s))
		printf("No new or modified files.\n");
	else
		need_to_write = true;

	if (remove_missing || ignore_seconds) {
		bool expired = false;
		bool missing = false;
		for (auto it = sha1s.begin(); it != sha1s.end();) {
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

	char sha1s_tmp[PATH_MAX] = { };
	strncpy(sha1s_tmp, filename, PATH_MAX);
	strncat(sha1s_tmp, ".tmp", PATH_MAX);
	if (sha1s_tmp[PATH_MAX - 1])
		error(EXIT_FAILURE, EINVAL, "filename too long");
	FILE *f = fopen(sha1s_tmp, "wb");
	if (!f)
		error(EXIT_FAILURE, errno, "failed to open %s", sha1s_tmp);

	for (auto it = sha1s.begin(); it != sha1s.end(); ++it) {
		if (remove_missing && !it->second.touched())
			continue;
		char modified[128];
		size_t modified_sz = snprintf(modified, 128, "%ld.%ld",
		    it->second.modified().tv_sec, it->second.modified().tv_nsec);
		if ((fwrite(it->first.c_str(), it->first.size(), 1, f) < 0) ||
		    (fwrite("", 1, 1, f) < 0) ||
		    (fwrite(modified, modified_sz, 1, f) < 0) ||
		    (fwrite("", 1, 1, f) < 0) ||
		    (fwrite(it->second.hash().c_str(), it->second.hash().size(), 1, f) < 0) ||
		    (fwrite("\0\n", 2, 1, f) < 0))
			error(EXIT_FAILURE, errno, "fwrite");
	}

	if (fclose(f) != 0)
		error(EXIT_FAILURE, errno, "fclose");

	if (rename(sha1s_tmp, filename) != 0)
		error(EXIT_FAILURE, errno, "rename");

	return EXIT_SUCCESS;
}
