/**
 * This file is part of the CernVM File System.
 */
#define __STDC_FORMAT_MACROS

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <libgen.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "x509_helper_base64.h"
#include "x509_helper_check.h"
#include "x509_helper_fetch.h"
#include "x509_helper_globus.h"
#include "x509_helper_log.h"
#include "x509_helper_req.h"
#include "x509_helper_voms.h"

#include "scitoken_helper_loader.h"
#include "scitoken_helper_fetch.h"

#include "json.h"
typedef struct json_value JSON;

#ifdef __APPLE__
#define strdupa(s) strcpy(/* NOLINT(runtime/printf) */\
  reinterpret_cast<char *>(alloca(strlen((s)) + 1)), (s))
#endif

using namespace std;  // NOLINT


/**
 * Get bytes from stdin.
 */
static void Read(void *buf, size_t nbyte) {
  int num_bytes;
  do {
    num_bytes = read(fileno(stdin), buf, nbyte);
  } while ((num_bytes < 0) && (errno == EINTR));
  assert(num_bytes >= 0);
  assert(static_cast<size_t>(num_bytes) == nbyte);
}


/**
 * Send bytes to stdout.
 */
static void Write(const void *buf, size_t nbyte) {
  int num_bytes;
  do {
    num_bytes = write(fileno(stdout), buf, nbyte);
  } while ((num_bytes < 0) && (errno == EINTR));
  assert((num_bytes >= 0) && (static_cast<size_t>(num_bytes) == nbyte));
}


/**
 * Reads a complete message from the cvmfs client.
 */
static string ReadMsg() {
  uint32_t version;
  uint32_t length;
  Read(&version, sizeof(version));
  assert(version == kProtocolVersion);
  Read(&length, sizeof(length));
  if (length == 0)
    return "";
  char *buf = reinterpret_cast<char *>(alloca(length));
  Read(buf, length);
  return string(buf, length);
}


/**
 * Sends a (JSON formatted) message back to the cvmfs client.
 */
static void WriteMsg(const string &msg) {
  struct {
    uint32_t version;
    uint32_t length;
  } header;
  header.version = kProtocolVersion;
  header.length = msg.length();
  Write(&header, sizeof(header));
  Write(msg.data(), header.length);
}


static void ParseHandshakeInit(const string &msg) {
  block_allocator allocator(2048);
  char *err_pos; char *err_desc; int err_line;
  JSON *json = json_parse(strdupa(msg.c_str()),
                          &err_pos, &err_desc, &err_line,
                          &allocator);
  assert((json != NULL) && (json->first_child != NULL));
  json = json->first_child;
  assert((string(json->name) == "cvmfs_authz_v1"));
  json = json->first_child;
  while (json) {
    string name(json->name);
    if (name == "debug_log") {
      SetLogAuthzDebug(string(json->string_value) + ".authz");
    } else if (name == "fqrn") {
      LogAuthz(kLogAuthzDebug, "fqrn is %s", json->string_value);
      SetLogAuthzSyslogPrefix(string(json->string_value));
    } else if (name == "syslog_level") {
      SetLogAuthzSyslogLevel(json->int_value);
    } else if (name == "syslog_facility") {
      SetLogAuthzSyslogFacility(json->int_value);
    }
    json = json->next_sibling;
  }
}


/**
 * Extracts the information from a "verify" request from the cvmfs client.
 */
static AuthzRequest ParseRequest(const string &msg) {
  block_allocator allocator(2048);
  char *err_pos; char *err_desc; int err_line;
  JSON *json = json_parse(strdupa(msg.c_str()),
                          &err_pos, &err_desc, &err_line,
                          &allocator);
  assert((json != NULL) && (json->first_child != NULL));
  AuthzRequest result;
  json = json->first_child;
  assert((string(json->name) == "cvmfs_authz_v1"));
  json = json->first_child;
  while (json) {
    string name(json->name);
    if (name == "uid") {
      result.uid = json->int_value;
    } else if (name == "gid") {
      result.gid = json->int_value;
    } else if (name == "pid") {
      result.pid = json->int_value;
    } else if (name == "membership") {
      result.membership = Debase64(string(json->string_value));
    } else if (name == "msgid") {
      if (json->int_value == 4) {  /* kAuthzMsgQuit */
        LogAuthz(kLogAuthzDebug, "shut down");
        // TODO(jblomer): we might want to properly cleanup
        exit(0);
      }
    }
    json = json->next_sibling;
  }
  return result;
}


/**
 * This binary is supposed to be called from the cvmfs client, not stand-alone.
 */
static void CheckCallContext() {
  if (getenv("CVMFS_AUTHZ_HELPER") == NULL) {
    printf("This program is supposed to be called from the CernVM-FS client.");
    printf("\n");
    abort();
  }
}


int main(int argc, char **argv) {
  CheckCallContext();

  // Handshake
  string msg = ReadMsg();
  ParseHandshakeInit(msg);
  GlobusLib::GetInstance();
  VomsLib::GetInstance();
  WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":1,\"revision\":0}}");
  LogAuthz(kLogAuthzDebug | kLogAuthzSyslog,
           "x509 authz helper invoked, connected to cvmfs process %d",
           getppid());

  CheckSciToken_t checker = NULL;
  if (strcmp(basename(argv[0]), "cvmfs_scitoken_helper") == 0) {
    checker = SciTokenLib::GetInstance();
  }
  LogAuthz(kLogAuthzDebug, "Executable: %s", basename(argv[0]));

  while (true) {
    msg = ReadMsg();
    LogAuthz(kLogAuthzDebug, "got authz request %s", msg.c_str());
    AuthzRequest request = ParseRequest(msg);
    string proxy;

    // Try SciTokens first, if it was invoked as the cvmfs_scitoken_helper
    if (checker) {
      LogAuthz(kLogAuthzDebug, "Using SciTokens checker");
      // Get the environment variable CVMFS_TOKEN_VARNAME
      const char* var_name;
      if (getenv("CVMFS_TOKEN_VARNAME")) {
        var_name = getenv("CVMFS_TOKEN_VARNAME");
      } else {
        var_name = "TOKEN";
      }
      FILE *fp_token = GetSciToken(request, &proxy, var_name);
      // This will close fp_proxy along the way.
      if (fp_token) {
        LogAuthz(kLogAuthzDebug, "Calling SciTokens checker");
        StatusSciTokenValidation validation_status =
          (*checker)(request.membership.c_str(), fp_token);
        LogAuthz(kLogAuthzDebug, "validation status is %d", validation_status);

        if (validation_status == kCheckTokenGood) {
          WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":3,\"revision\":0,"
                    "\"status\":0,\"bearer_token\":\"" + proxy + "\"}}");
          continue;
        }
      }
      
    }

    // The rest of this is trying with the x509 proxy
    FILE *fp_proxy = GetX509Proxy(request, &proxy);
    if (fp_proxy == NULL) {
      // kAuthzNotFound, 5 seconds TTL
      LogAuthz(kLogAuthzDebug, "reply 'proxy not found'");
      WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":3,\"revision\":0,"
                "\"status\":1,\"ttl\":5}}");
      continue;
    }

    // This will close fp_proxy along the way.
    StatusX509Validation validation_status =
      CheckX509Proxy(request.membership, fp_proxy);
    LogAuthz(kLogAuthzDebug, "validation status is %d", validation_status);
    switch (validation_status) {
      case kCheckX509Invalid:
        WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":3,\"revision\":0,"
                "\"status\":2,\"ttl\":5}}");
        break;
      case kCheckX509NotMember:
        WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":3,\"revision\":0,"
                  "\"status\":3,\"ttl\":5}}");
        break;
      case kCheckX509Good:
        WriteMsg("{\"cvmfs_authz_v1\":{\"msgid\":3,\"revision\":0,"
                  "\"status\":0,\"x509_proxy\":\"" + Base64(proxy) + "\"}}");
        break;
      default:
        abort();
    }
  }

  return 0;
}
