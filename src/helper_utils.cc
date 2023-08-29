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

/**
 * Opens a read-only file pointer to the proxy certificate as a given user.
 * The path is either taken from X509_USER_PROXY environment from the given pid
 * or it is the default location /tmp/x509up_u<UID>
 */
FILE *GetFile(const std::string &env_name, pid_t pid, uid_t uid, gid_t gid, const std::string &default_path)
{
  char path[PATH_MAX];
  if (!GetPathFromEnv(env_name, pid, PATH_MAX, path)) {
    
    // If there is a default path, use that
    if (default_path.size()) {
      LogAuthz(kLogAuthzDebug, "could not find %s in environment, trying default location of %s", env_name.c_str(), default_path.c_str());
      strncpy(path, default_path.c_str(), PATH_MAX);
    } else {
      LogAuthz(kLogAuthzDebug, "could not find %s in environment", env_name.c_str());
      return NULL;
    }
  }
  else
      LogAuthz(kLogAuthzDebug, "looking in %s from %s", path, env_name.c_str());

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

  int fd = open("/", O_RDONLY);  // Open FD to old root directory.
  int fd2 = open(".", O_RDONLY); // Open FD to old $CWD
  if ((fd == -1) || (fd2 == -1)) {
    seteuid(olduid);
    if (fd != -1) {close(fd);}
    if (fd2 != -1) {close(fd2);}
    return NULL;
  }

  // If we can't chroot, we might be running this binary unprivileged -
  // don't try subsequent changes.
  bool can_chroot = true;
  if (-1 == chdir(container_cwd)) { // Change directory to same one as process.
    can_chroot = false;
  }
  if (can_chroot && (-1 == chroot(container_path))) {
    if (-1 == fchdir(fd)) {
      // Unable to restore original state!  Abort...
      abort();
    }
    can_chroot = false;
  }

  setegid(gid);
  seteuid(uid);

  FILE *fp = fopen(path, "r");

  seteuid(0); // Restore root privileges.
  if (can_chroot &&
       ((-1 == fchdir(fd)) || // Change to old root directory so we can reset chroot.
        (-1 == chroot(".")) ||
        (-1 == fchdir(fd2)) // Change to original $CWD
       )
     ) {
    abort();
  }
  setegid(oldgid); // Restore remaining privileges.
  seteuid(olduid);
  close(fd);
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

