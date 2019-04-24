/**
 * This file is part of the CernVM File System.
 */

#include "x509_helper_fetch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <cassert>
#include <climits>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "x509_helper_log.h"
#include "helper_utils.h"

using namespace std;  // NOLINT


FILE *GetX509Proxy(
const AuthzRequest &authz_req, string *proxy) {
  assert(proxy != NULL);

  stringstream default_path;
  default_path << "/tmp/x509up_u" << authz_req.uid;
  string default_path_str = default_path.str();
  if (default_path_str.size() > PATH_MAX) {
    default_path_str = "";
  }

  FILE *fproxy =
    GetFile("X509_USER_PROXY", authz_req.pid, authz_req.uid, authz_req.gid, default_path_str);
  if (fproxy == NULL) {
    LogAuthz(kLogAuthzDebug, "no proxy found for %s",
             authz_req.Ident().c_str());
    return NULL;
  }

  proxy->clear();
  const unsigned kBufSize = 1024;
  char buf[kBufSize];
  unsigned nbytes;
  do {
    nbytes = fread(buf, 1, kBufSize, fproxy);
    if (nbytes > 0)
      proxy->append(string(buf, nbytes));
  } while (nbytes == kBufSize);

  rewind(fproxy);
  return fproxy;
}
