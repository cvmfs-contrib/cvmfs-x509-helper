/**
 * This file is part of the CernVM File System.
 */

#ifndef CVMFS_AUTHZ_HELPER_UTILS_H_
#define CVMFS_AUTHZ_HELPER_UTILS_H_

#include <stdlib.h>
#include <unistd.h>
#include <string>

using namespace std;

FILE *GetFile(const std::string &env_name, const pid_t pid, const uid_t uid, const gid_t gid);

#endif // CVMFS_AUTHZ_HELPER_UTILS_H_

