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
#include <fstream>

#include "x509_helper_log.h"

using namespace std;  // NOLINT

/**
 * For a given pid, extracts the env_name path from the foreign
 * process' environment.  Stores the resulting path in the user provided buffer
 * path.
 */
 
static bool GetFileFromEnv(
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
    return false;
  }
  int olduid = geteuid();
  // NOTE: we ignore return values of these syscalls; this code path
  // will work if cvmfs is FUSE-mounted as an unprivileged user.
  seteuid(0);

  fstream env_file;
  env_file.open(path, std::fstream::in);
  if (env_file.fail()) {
    LogAuthz(kLogAuthzSyslogErr | kLogAuthzDebug,
             "failed to open environment file for pid %d.", pid);
    seteuid(olduid);
    return false;
  }

  string to_find = env_name + "=";
  string cur_str;
  bool set_env = false;
  // Loop through the file by the token "\0"
  while( getline(env_file, cur_str, '\0')) {
    size_t pos = cur_str.find(to_find);
    // Make sure the string is found and it's at the beginning
    if (pos != string::npos && pos == 0) {
      set_env = true;
      strncpy(path, cur_str.substr(pos + to_find.length()).c_str(), path_len);
      break;
    }
  }

  env_file.close();
  seteuid(olduid);
  return set_env;


}


/**
 * Opens a read-only file pointer to the proxy certificate as a given user.
 * The path is either taken from X509_USER_PROXY environment from the given pid
 * or it is the default location /tmp/x509up_u<UID>
 */
FILE *GetFile(const std::string &env_name, pid_t pid, uid_t uid, gid_t gid, const std::string &default_path)
{
  char path[PATH_MAX];
  if (!GetFileFromEnv(env_name, pid, PATH_MAX, path)) {
    
    // If there is a default path, use that
    if (default_path.size()) {
      LogAuthz(kLogAuthzDebug, "could not find file in environment, trying default location of %s", default_path.c_str());
      strncpy(path, default_path.c_str(), PATH_MAX);
    } else {
      LogAuthz(kLogAuthzDebug, "could not find file in environment");
      return NULL;
    }

  }
  LogAuthz(kLogAuthzDebug, "looking for proxy in file %s", path);

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
