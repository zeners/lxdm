#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>

#include "cgroup.h"

#define SYSTEMD_CGROUP_CONTROLLER "name=systemd"

#define new(t, n) ((t*) malloc(sizeof(t)*(n)))

#define streq(a,b) (strcmp((a),(b)) == 0)

char *truncate_nl(char *s) {
        assert(s);

        s[strcspn(s, "\n\r")] = 0;
        return s;
}

bool endswith(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return true;

        if (sl < pl)
                return false;

        return memcmp(s + sl - pl, postfix, pl) == 0;
}

bool startswith(const char *s, const char *prefix) {
        size_t sl, pl;

        assert(s);
        assert(prefix);

        sl = strlen(s);
        pl = strlen(prefix);

        if (pl == 0)
                return true;

        if (sl < pl)
                return false;

        return memcmp(s, prefix, pl) == 0;
}

char *strnappend(const char *s, const char *suffix, size_t b) {
        size_t a;
        char *r;

        if (!s && !suffix)
                return strdup("");

        if (!s)
                return strndup(suffix, b);

        if (!suffix)
                return strdup(s);

        assert(s);
        assert(suffix);

        a = strlen(s);

        if (!(r = new(char, a+b+1)))
                return NULL;

        memcpy(r, s, a);
        memcpy(r+a, suffix, b);
        r[a+b] = 0;

        return r;
}

char *strappend(const char *s, const char *suffix) {
        return strnappend(s, suffix, suffix ? strlen(suffix) : 0);
}

int parent_of_path(const char *path, char **_r) {
        const char *e, *a = NULL, *b = NULL, *p;
        char *r;
        bool slash = false;

        assert(path);
        assert(_r);

        if (!*path)
                return -EINVAL;

        for (e = path; *e; e++) {

                if (!slash && *e == '/') {
                        a = b;
                        b = e;
                        slash = true;
                } else if (slash && *e != '/')
                        slash = false;
        }

        if (*(e-1) == '/')
                p = a;
        else
                p = b;

        if (!p)
                return -EINVAL;

        if (p == path)
                r = strdup("/");
        else
                r = strndup(path, p-path);

        if (!r)
                return -ENOMEM;

        *_r = r;
        return 0;
}

int path_is_mount_point(const char *t) {
        struct stat a, b;
        char *parent;
        int r;

        if (lstat(t, &a) < 0) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        if ((r = parent_of_path(t, &parent)) < 0)
                return r;

        r = lstat(parent, &b);
        free(parent);

        if (r < 0)
                return -errno;

        return a.st_dev != b.st_dev;
}

char *path_kill_slashes(char *path) {
        char *f, *t;
        bool slash = false;

        /* Removes redundant inner and trailing slashes. Modifies the
         * passed string in-place.
         *
         * ///foo///bar/ becomes /foo/bar
         */

        for (f = path, t = path; *f; f++) {

                if (*f == '/') {
                        slash = true;
                        continue;
                }

                if (slash) {
                        slash = false;
                        *(t++) = '/';
                }

                *(t++) = *f;
        }

        /* Special rule, if we are talking of the root directory, a
        trailing slash is good */

        if (t == path && slash)
                *(t++) = '/';

        *t = 0;
        return path;
}

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs) {
        const char *p;
        char *mp;
        int r;
        static __thread bool good = false;

        assert(controller);
        assert(fs);

        /* This is a very minimal lookup from controller names to
         * paths. Since we have mounted most hierarchies ourselves
         * should be kinda safe, but eventually we might want to
         * extend this to have a fallback to actually check
         * /proc/mounts. Might need caching then. */

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                p = "systemd";
        else if (startswith(controller, "name="))
                p = controller + 5;
        else
                p = controller;

        if (asprintf(&mp, "/sys/fs/cgroup/%s", p) < 0)
                return -ENOMEM;

        if (!good) {
                if ((r = path_is_mount_point(mp)) <= 0) {
                        free(mp);
                        return r < 0 ? r : -ENOENT;
                }

                /* Cache this to save a few stat()s */
                good = true;
        }

        if (path && suffix)
                r = asprintf(fs, "%s/%s/%s", mp, path, suffix);
        else if (path)
                r = asprintf(fs, "%s/%s", mp, path);
        else if (suffix)
                r = asprintf(fs, "%s/%s", mp, suffix);
        else {
                path_kill_slashes(mp);
                *fs = mp;
                return 0;
        }

        free(mp);
        path_kill_slashes(*fs);
        return r < 0 ? -ENOMEM : 0;
}

int cg_enumerate_processes(const char *controller, const char *path, FILE **_f) {
        char *fs;
        int r;
        FILE *f;

        assert(controller);
        assert(path);
        assert(_f);

        if ((r = cg_get_path(controller, path, "cgroup.procs", &fs)) < 0)
                return r;

        f = fopen(fs, "re");
        free(fs);

        if (!f)
                return -errno;

        *_f = f;
        return 0;
}

int cg_read_pid(FILE *f, pid_t *_pid) {
        unsigned long ul;

        /* Note that the cgroup.procs might contain duplicates! See
         * cgroups.txt for details. */

        errno = 0;
        if (fscanf(f, "%lu", &ul) != 1) {

                if (feof(f))
                        return 0;

                return errno ? -errno : -EIO;
        }

        if (ul <= 0)
                return -EIO;

        *_pid = (pid_t) ul;
        return 1;
}

int cg_get_by_pid(const char *controller, pid_t pid, char **path) {
        int r;
        char *p = NULL;
        FILE *f;
        char *fs;
        size_t cs;

        assert(controller);
        assert(path);
        assert(pid >= 0);

        if (pid == 0)
                pid = getpid();

        if (asprintf(&fs, "/proc/%lu/cgroup", (unsigned long) pid) < 0)
                return -ENOMEM;

        f = fopen(fs, "re");
        free(fs);

        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        cs = strlen(controller);

        while (!feof(f)) {
                char line[LINE_MAX];
                char *l;

                errno = 0;
                if (!(fgets(line, sizeof(line), f))) {
                        if (feof(f))
                                break;

                        r = errno ? -errno : -EIO;
                        goto finish;
                }

                truncate_nl(line);

                if (!(l = strchr(line, ':')))
                        continue;

                l++;
                if (strncmp(l, controller, cs) != 0)
                        continue;

                if (l[cs] != ':')
                        continue;

                if (!(p = strdup(l + cs + 1))) {
                        r = -ENOMEM;
                        goto finish;
                }

                *path = p;
                r = 0;
                goto finish;
        }

        r = -ENOENT;

finish:
        fclose(f);

        return r;
}

int cg_get_user_path(char **path) {
        char *root, *p;

        assert(path);

        /* Figure out the place to put user cgroups below. We use the
         * same as PID 1 has but with the "/system" suffix replaced by
         * "/user" */

        if (cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 1, &root) < 0)
                p = strdup("/user");
        else {
                if (endswith(root, "/system"))
                        root[strlen(root) - 7] = 0;
                else if (streq(root, "/"))
                        root[0] = 0;

                p = strappend(root, "/user");
                free(root);
        }

        if (!p)
                return -ENOMEM;

        *path = p;
        return 0;
}

int cg_rmdir(const char *controller, const char *path) {
        char *p;
        int r;

        if ((r = cg_get_path(controller, path, NULL, &p)) < 0)
                return r;

        r = rmdir(p);
        free(p);

        return r < 0 ? -errno : 0;
}

int cg_kill(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self) {
        bool done = false;
        int r, ret = 0;
        pid_t my_pid;
        FILE *f = NULL;

        assert(controller);
        assert(path);
        assert(sig >= 0);

        /* This goes through the tasks list and kills them all. This
         * is repeated until no further processes are added to the
         * tasks list, to properly handle forking processes */

        my_pid = getpid();

        do {
                pid_t pid = 0;
                done = true;

                if ((r = cg_enumerate_processes(controller, path, &f)) < 0) {
                        if (ret >= 0 && r != -ENOENT)
                                ret = r;

                        goto finish;
                }

                while ((r = cg_read_pid(f, &pid)) > 0) {

                        if (pid == my_pid && ignore_self)
                                continue;

                        /* If we haven't killed this process yet, kill
                         * it */
                        if (kill(pid, sig) < 0) {
                                if (ret >= 0 && errno != ESRCH)
                                        ret = -errno;
                        } else if (ret == 0) {

                                if (sigcont)
                                        kill(pid, SIGCONT);

                                ret = 1;
                        }

                        done = false;
                }

                if (r < 0) {
                        if (ret >= 0)
                                ret = r;

                        goto finish;
                }

                fclose(f);
                f = NULL;

                /* To avoid racing against processes which fork
                 * quicker than we can kill them we repeat this until
                 * no new pids need to be killed. */

        } while (!done);

finish:
        if (f)
                fclose(f);

        return ret;
}

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **_d) {
        char *fs;
        int r;
        DIR *d;

        assert(controller);
        assert(path);
        assert(_d);

        /* This is not recursive! */

        if ((r = cg_get_path(controller, path, NULL, &fs)) < 0)
                return r;

        d = opendir(fs);
        free(fs);

        if (!d)
                return -errno;

        *_d = d;
        return 0;
}

int cg_read_subgroup(DIR *d, char **fn) {
        struct dirent *de;

        assert(d);

        errno = 0;
        while ((de = readdir(d))) {
                char *b;

                if (de->d_type != DT_DIR)
                        continue;

                if (streq(de->d_name, ".") ||
                    streq(de->d_name, ".."))
                        continue;

                if (!(b = strdup(de->d_name)))
                        return -ENOMEM;

                *fn = b;
                return 1;
        }

        if (errno)
                return -errno;

        return 0;
}

int cg_kill_recursive(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self, bool rem) {
        int r, ret = 0;
        DIR *d = NULL;
        char *fn;

        assert(path);
        assert(controller);
        assert(sig >= 0);

        ret = cg_kill(controller, path, sig, sigcont, ignore_self);

        if ((r = cg_enumerate_subgroups(controller, path, &d)) < 0) {
                if (ret >= 0 && r != -ENOENT)
                        ret = r;

                goto finish;
        }

        while ((r = cg_read_subgroup(d, &fn)) > 0) {
                char *p = NULL;

                r = asprintf(&p, "%s/%s", path, fn);
                free(fn);

                if (r < 0) {
                        if (ret >= 0)
                                ret = -ENOMEM;

                        goto finish;
                }

                r = cg_kill_recursive(controller, p, sig, sigcont, ignore_self, rem);
                free(p);

                if (r != 0 && ret >= 0)
                        ret = r;
        }

        if (r < 0 && ret >= 0)
                ret = r;

        if (rem)
                if ((r = cg_rmdir(controller, path)) < 0) {
                        if (ret >= 0 &&
                            r != -ENOENT &&
                            r != -EBUSY)
                                ret = r;
                }

finish:
        if (d)
                closedir(d);

        return ret;
}

int cg_kill_self(void)
{
	char *path;
	int ret;
	ret=cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER,getpid(),&path);
	if(ret!=0)
		return ret;
	ret=cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER,path,SIGTERM,false,true,false);
	free(path);
	return ret;
}
