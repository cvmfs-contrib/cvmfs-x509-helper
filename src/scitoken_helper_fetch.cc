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
#include <string>
#include <sstream>

#include "x509_helper_log.h"
#include "helper_utils.h"

using namespace std;  // NOLINT

FILE *GetSciToken(
const AuthzRequest &authz_req, string *proxy, const string &var_name) {
  assert(proxy != NULL);

  string env_name = var_name;

  FILE *ftoken = GetEnvVarFile("BEARER_TOKEN", authz_req.pid);
  if (ftoken != NULL) {
    LogAuthz(kLogAuthzDebug, "found token in $BEARER_TOKEN");
    return ftoken;
  } 

  stringstream default_path;
  FILE *fruntimedir = GetEnvVarFile("XDG_RUNTIME_DIR", authz_req.pid);
  string runtimedir;
  if (fruntimedir != NULL) {
    GetStringFromFile(fruntimedir, runtimedir);
    fclose(fruntimedir);
  }
  if (runtimedir.size()) {
    default_path << runtimedir;
  }
  else {
    default_path << "/tmp";
  }
  default_path << "/bt_u" << authz_req.uid;
  string default_path_str = default_path.str();
  if (default_path_str.size() > PATH_MAX) {
    LogAuthz(kLogAuthzDebug, "default path string bigger than PATH_MAX, ignoring it");
    default_path_str = "";
  }

  FILE *fproxy =
    GetFile(env_name.c_str(), authz_req.pid, authz_req.uid, authz_req.gid, default_path_str);
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
      proxy->append(string(buf, nbytes));
  } while (nbytes == kBufSize);

  // Remove the newline at the end of the token
  if ((*proxy)[proxy->size()-1] == '\n') {
    proxy->erase(proxy->size()-1);
  }

  rewind(fproxy);
  return fproxy;
}
