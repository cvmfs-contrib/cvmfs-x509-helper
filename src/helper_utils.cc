/**
 * This file is part of the CernVM File System.
 */

#include "helper_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <cassert>
#include <climits>
#include <cstdio>
#include <cstring>
#include <vector>
#include <sched.h>
#include <wait.h>

#include "x509_helper_log.h"

using namespace std;  // NOLINT

/**
 * For a given pid, locates the env_name from the foreign process'
 * environment.  Returns the FILE pointer positioned after the '=' in
 * the environ file, or NULL if the environment variable is not found.
 */
 
static FILE *GetFileFromEnv(
  const std::string &env_name,
  const pid_t pid,
  const size_t path_len,
  char *path)
{
  assert(path_len > 0);

  if (snprintf(path, path_len, "/proc/%d/environ", pid) >=
      static_cast<int>(path_len))
  {
    if (errno == 0) {errno = ERANGE;}
    return NULL;
  }
  int olduid = geteuid();
  // NOTE: we ignore return values of these syscalls; this code path
  // will work if cvmfs is FUSE-mounted as an unprivileged user.
  seteuid(0);

  FILE *env_file = fopen(path, "r");
  seteuid(olduid);
  if (env_file == NULL) {
    LogAuthz(kLogAuthzSyslogErr | kLogAuthzDebug,
             "failed to open environment file for pid %d.", pid);
    return NULL;
  }

  string cur_str;
  int c;
  do {
    // Search for the variable
    cur_str = "";
    do {
      // Loop until find an equal sign
      c = fgetc(env_file);
      if (c == '=') {
        if (cur_str == env_name) {
          // Got a match
          return env_file;
        } else {
          // Not this one, skip the value until the next null character
          do {
            c = fgetc(env_file);
          } while ((c != EOF) && (c != '\0'));
        }
      } else if (c != EOF) {
        // append the character to the variable name
        cur_str.append(1, c);
      }
    } while ((c != EOF) && (c != '\0'));
  } while (c != EOF);

  fclose(env_file);
  return NULL;
}

/**
 * For a given pid, extracts the env_name path from the foreign process'
 * environment.  Stores the resulting path in the user provided buffer
 * path.
 */
 
static bool GetPathFromEnv(
  const std::string &env_name,
  const pid_t pid,
  const size_t path_len,
  char *path)
{
  FILE *fp = GetFileFromEnv(env_name, pid, path_len, path);
  if (fp == NULL) {
    return false;
  }
  string str;
  GetStringFromFile(fp, str);
  fclose(fp);
  strncpy(path, str.c_str(), path_len);
  return true;
}


/**
 * Gets a FILE pointer pointing to the value of an environment variable,
 * null terminated.  Returns NULL if the variable was not found.
 */ 
FILE *GetEnvVarFile(const std::string &env_name, const pid_t pid)
{
  char path[PATH_MAX];
  return GetFileFromEnv(env_name, pid, PATH_MAX, path);
}

/* Parameters to GetFileInNs */
struct getFileInNsParams {
  pid_t pid;
  uid_t uid;
  gid_t gid;
  char *env_path;
  FILE *fp;
};

/**
 * Thread function for opening a file inside a user and mount namespace.
 * The passed in parameter is of type void * but is a reference to 
 * a structure of type getFileInNsParams.
 * Returns the open FILE object in the params.
 * Returns non-zero for error and 0 for success.
 */
static int GetFileInNs(void *t) {
  struct getFileInNsParams *p = (struct getFileInNsParams *) t;

  // Set real gid and uid in this thread, not just effective, else
  // it interferes with the use of the unprivileged user namespace.
  // NOTE: this is depending on the fact that CLONE_THREAD was not
  // used because otherwise the setting is shared between threads. 
  // See the setuid(2), clone(2), and nptl(7) man pages.
  setgid(p->gid);
  setuid(p->uid);

  char path[PATH_MAX];
  if (snprintf(path, PATH_MAX, "/proc/%d/ns/user", p->pid) >= PATH_MAX) {
    if (errno == 0) {errno = ERANGE;}
    return errno;
  }
  int fd1 = open(path, O_RDONLY);
  int fd2 = -1;
  if (-1 == fd1) {
    // Couldn't open new user namespace, see if it works without
    LogAuthz(kLogAuthzDebug, "could not open new user namespace %s", path);
  } else if (-1 == setns(fd1, CLONE_NEWUSER)) {
    // Couldn't switch to new user namespace, try without
    close(fd1);
    fd1 = -1;
    LogAuthz(kLogAuthzDebug, "could not switch to user namespace %s", path);
  } else {
    if (snprintf(path, PATH_MAX, "/proc/%d/ns/mnt", p->pid) >= PATH_MAX) {
      if (errno == 0) {errno = ERANGE;}
      return errno;
    }
    fd2 = open(path, O_RDONLY);
    int saveerrno = errno;
    if (-1 == fd2) {
      LogAuthz(kLogAuthzDebug, "could not open new mnt namespace %s", path);
      // Very strange that couldn't open new mnt namespace when user
      // namespace worked.  Just return an error.
      close(fd1);
      return saveerrno;
    } else if (-1 == setns(fd2, CLONE_NEWNS)) {
      saveerrno = errno;
      // Likewise strange that couldn't switch to new mnt namespace
      LogAuthz(kLogAuthzDebug, "could not switch to mnt namespace %s", path);
      close(fd1);
      close(fd2);
      return saveerrno;
    }
    LogAuthz(kLogAuthzDebug, "entered user and mnt namespace of %d", p->pid);
  }
  p->fp = fopen(p->env_path, "r");
  if (fd1 != -1) close(fd1);
  if (fd2 != -1) close(fd2);
  return 0;
}

/**
 * Opens a read-only file pointer to the proxy certificate as a given user.
 * The path is either taken from X509_USER_PROXY environment from the given pid
 * or it is the default location /tmp/x509up_u<UID>
 */
FILE *GetFile(const std::string &env_name, pid_t pid, uid_t uid, gid_t gid, const std::string &default_path)
{
  char env_path[PATH_MAX];
  if (!GetPathFromEnv(env_name, pid, PATH_MAX, env_path)) {
    
    // If there is a default path, use that
    if (default_path.size()) {
      LogAuthz(kLogAuthzDebug, "could not find %s in environment, trying default location of %s", env_name.c_str(), default_path.c_str());
      strncpy(env_path, default_path.c_str(), PATH_MAX);
    } else {
      LogAuthz(kLogAuthzDebug, "could not find %s in environment", env_name.c_str());
      return NULL;
    }
  }
  else
      LogAuthz(kLogAuthzDebug, "looking in %s from %s", env_path, env_name.c_str());

  /**
   * If the target process is running inside a container, then we must
   * adjust our fopen below for a chroot.
   */
  char container_path[PATH_MAX];
  if (snprintf(container_path, PATH_MAX, "/proc/%d/root", pid) >=
      PATH_MAX) {
    if (errno == 0) {errno = ERANGE;}
    return NULL;
  }
  char container_cwd[PATH_MAX];
  if (snprintf(container_cwd, PATH_MAX, "/proc/%d/cwd", pid) >=
      PATH_MAX) {
    if (errno == 0) {errno = ERANGE;}
    return NULL;
  }

  int olduid = geteuid();
  int oldgid = getegid();
  // NOTE the sequencing: we must be eUID 0
  // to change the UID and GID.
  seteuid(0);

  int fd1 = open("/", O_RDONLY); // Open FD to old root directory.
  int fd2 = open(".", O_RDONLY); // Open FD to old $CWD
  if ((fd1 == -1) || (fd2 == -1)) {
    seteuid(olduid);
    if (fd1 != -1) {close(fd1);}
    if (fd2 != -1) {close(fd2);}
    return NULL;
  }

  // If we can't chroot, we might be running this binary unprivileged -
  // don't try subsequent changes.
  bool can_chroot = true;
  if (-1 == chdir(container_cwd)) { // Change directory to same one as process.
    can_chroot = false;
  } else if (-1 == chroot(container_path)) {
    if (-1 == fchdir(fd1)) {
      // Unable to restore original state!  Abort...
      abort();
    }
    can_chroot = false;
    LogAuthz(kLogAuthzDebug, "could not chroot to %s", container_path);
  } else {
    LogAuthz(kLogAuthzDebug, "chrooted to %s", container_path);
  }

  FILE *fp = NULL;
  if (!can_chroot) {
    // Couldn't chroot, which can happen at least starting in RHEL8 when
    // trying to chroot to an unprivileged user namespace as root.
    // Instead, create a thread to try to enter user and mount namespaces
    // as the user.  That has to be done in a thread in order to be able
    // to return to the previous namespace.
    struct getFileInNsParams params;
    params.pid = pid;
    params.uid = uid;
    params.gid = gid;
    params.env_path = env_path;
    params.fp = NULL;
    char stack[128 * 1024];

    pid_t cpid = clone(GetFileInNs, stack + sizeof(stack),
                        CLONE_VM | CLONE_FILES | SIGCHLD, (void *)&params);
    if (cpid == -1) {
      LogAuthz(kLogAuthzDebug, "could not clone thread");
      abort();
    }
    int status = 0;
    if (waitpid(cpid, &status, 0) == -1) {
      LogAuthz(kLogAuthzDebug, "could not wait for cloned thread");
      abort();
    }
    if (status != 0) {
      LogAuthz(kLogAuthzDebug, "clone returned an error: %d", status);
      abort();
    }
    fp = params.fp;
  } else {
    setegid(gid);
    seteuid(uid);
    fp = fopen(env_path, "r");
    seteuid(0); // Restore root privileges.
  }

  if (can_chroot &&
       ((-1 == fchdir(fd1)) || // Change to old root directory so we can reset chroot.
        (-1 == chroot(".")) ||
        (-1 == fchdir(fd2)) // Change to original $CWD
       )
     ) {
    abort();
  }
  setegid(oldgid); // Restore remaining privileges.
  seteuid(olduid);
  close(fd1);
  close(fd2);

  return fp;
}

/**
 * Reads a string from a FILE pointer, possibly null terminated.
 */
void GetStringFromFile(FILE *fp, string &str) {
  size_t N=1024;  // making this const appears to trigger a compiler bug on
                  // EL8 at the break statement below, so leave it a variable
  str = "";
  while (true) {
    char buf[N+1];
    size_t read = fread((void *)&buf[0], 1, N, fp);
    if (ferror(fp)) {
      LogAuthz(kLogAuthzDebug, "error reading string from file");
      str = "";
      return;
    }
    buf[N] = '\0';
    int len = strlen(buf);
    if (len < read) { read = len; } // null terminated
    if (read) { str.append(string(buf, read)); }
    if (read < N) { break; }
    // If the string is larger than 1MB, then stop reading in
    // Possible malicious user
    if ( str.size() > (1024 * 1024) ) {
      LogAuthz(kLogAuthzDebug, "string larger than 1 MB");
      str = "";
      return;
    }
  }
}

