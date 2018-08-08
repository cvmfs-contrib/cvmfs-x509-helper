/**
 * This file is part of the CernVM File System.
 */

#ifndef CVMFS_AUTHZ_SCITOKEN_HELPER_CHECK_H_
#define CVMFS_AUTHZ_SCITOKEN_HELPER_CHECK_H_

#include <cstdio>
#include <string>

enum StatusSciTokenValidation {
  kCheckTokenGood,
  kCheckTokenInvalid,
};

StatusSciTokenValidation CheckSciToken(const std::string &membership,
                                    FILE *fp_token);

#endif  // CVMFS_AUTHZ_SCITOKEN_HELPER_CHECK_H_
