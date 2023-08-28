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
const AuthzRequest &authz_req, string *token, const string &var_name) {
  assert(token != NULL);

  string env_name = var_name;

  FILE *ftoken = GetEnvVarFile("BEARER_TOKEN", authz_req.pid);
  if (ftoken != NULL) {
    LogAuthz(kLogAuthzDebug, "found token in $BEARER_TOKEN");
  } 
  else {
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

    ftoken =
      GetFile(env_name.c_str(), authz_req.pid, authz_req.uid, authz_req.gid, default_path_str);
    if (ftoken == NULL) {
      LogAuthz(kLogAuthzDebug, "no token found for %s",
               authz_req.Ident().c_str());
      return NULL;
    }
  }

  long pos;
  if ((pos = ftell(ftoken)) == -1) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failure getting the ftoken position");
      return NULL;
  }

  token->clear();
  while(true) {
    int c = fgetc(ftoken);
    if (c == EOF) {
      if (ferror(ftoken)) {
        LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Error reading token file");
        return NULL;
      }
      break;
    }
    if (c == '\0') {
      // This will happen when reading from $BEARER_TOKEN environment
      break;
    }
    if (c == '\n') {
      // This will happen when reading from a file
      break;
    }
    *token += (unsigned char) c;
  }

  LogAuthz(kLogAuthzDebug, "token is %s", token->c_str());

  if (fseek(ftoken, pos, SEEK_SET) == -1) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failure setting the ftoken position");
      return NULL;
  }
  return ftoken;
}
