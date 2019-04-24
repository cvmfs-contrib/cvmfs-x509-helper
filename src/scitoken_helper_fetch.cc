/**
 * This file is part of the CernVM File System.
 */

#include "scitoken_helper_fetch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <cassert>
#include <climits>
#include <cstdio>
#include <cstring>

#include "x509_helper_log.h"
#include "helper_utils.h"

FILE *GetSciToken(
const AuthzRequest &authz_req, std::string *proxy, const std::string &var_name) {
  assert(proxy != NULL);

  FILE *fproxy =
    GetFile(var_name.c_str(), authz_req.pid, authz_req.uid, authz_req.gid, "");
  if (fproxy == NULL) {
    LogAuthz(kLogAuthzDebug, "no token found for %s",
             authz_req.Ident().c_str());
    return NULL;
  }

  proxy->clear();
  const unsigned kBufSize = 1024;
  char buf[kBufSize];
  unsigned nbytes;
  do {
    nbytes = fread(buf, 1, kBufSize, fproxy);
    if (ferror(fproxy)) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Error reading token file");
    }
    if (nbytes > 0)
      proxy->append(std::string(buf, nbytes));
  } while (nbytes == kBufSize);

  rewind(fproxy);
  return fproxy;
}
