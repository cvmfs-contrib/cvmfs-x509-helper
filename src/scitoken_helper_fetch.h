/**
 * This file is part of the CernVM File System.
 */

#ifndef CVMFS_AUTHZ_SCITOKEN_HELPER_FETCH_H_
#define CVMFS_AUTHZ_SCITOKEN_HELPER_FETCH_H_

#include <unistd.h>

#include <cstdio>
#include <string>

#include "x509_helper_req.h"

FILE *GetSciToken(const AuthzRequest &authz_req, std::string *proxy);

#endif  // CVMFS_AUTHZ_SCITOKEN_HELPER_FETCH_H_


