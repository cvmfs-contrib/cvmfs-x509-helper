/**
 * This file is part of the CernVM File System.
 */
#include "scitoken_helper_check.h"
#include "x509_helper_log.h"

#include <scitokens/scitokens.h>

#include <sys/types.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <sstream>
#include <string>
#include <map>
#include <memory>
#include <unistd.h>

using namespace std;  // NOLINT


__attribute__ ((visibility ("default")))
StatusSciTokenValidation CheckSciToken(const char* membership, FILE *fp_token) {

  LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Checking scitoken");

  SciToken scitoken;

  // Read in the entire scitoken into memory
  string token;
  const unsigned int N=1024;
  while (true) {
    char buf[N];
    size_t read = fread((void *)&buf[0], 1, N, fp_token);
    if (ferror(fp_token)) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Error reading token file");
      return kCheckTokenInvalid;
    }
    if (read) { token.append(string(buf, read)); }
    if (read < N) { break; }
    // If the token is larger than 1MB, then stop reading in the token
    // Possible malicious user
    if ( token.size() > (1024 * 1024) ) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "SciToken larger than 1 MB");
      return kCheckTokenInvalid;
    }
  }

  // Loop through the membership, looking for "https://" issuers
  map<string, string> issuers;
  vector<string> issuers_vec;
  std::istringstream iss(membership);
  string prefix("https://");

  // Look for issuers
  for (std::string line; std::getline(iss, line); ) {
    if (!line.compare(0, prefix.size(), prefix)) {
      // Check for the ";" delimiter
      std::size_t found = line.find(";");
      string issuer;
      string scope("/");
      if (found != std::string::npos) {
        issuer = line.substr(0, found);
        scope = line.substr(found + 1, line.length() + 1);
      } else {
        issuer = line;
      }
      issuers[issuer] = scope;
      issuers_vec.push_back(issuer);
    }
  }

  // Convert the vector into a null ended list of strings
  char** null_ended_list = new char*[issuers_vec.size()+1];
  for(std::vector<string>::size_type i = 0; i != issuers_vec.size(); i++) {
    char* tmp_char = strdup(issuers_vec[i].c_str());
    null_ended_list[i] = tmp_char;
  }
  null_ended_list[issuers_vec.size()] = NULL;

  // Remove the trailing new line from the token, if there is one
  if (token[token.size()-1] == '\n') {
    token.erase(token.size()-1);
  }

  char *err_msg = NULL;
  if (scitoken_deserialize(token.c_str(), &scitoken, null_ended_list, &err_msg)) {
    LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failed to deserialize scitoken: %s", err_msg);
    // Loop through and delete the issuers
    for (std::vector<string>::size_type i = 0; i < issuers_vec.size(); i++) {
      delete null_ended_list[i];
    }
    delete [] null_ended_list;
    return kCheckTokenInvalid;
  }
  for (std::vector<string>::size_type i = 0; i < issuers_vec.size(); i++) {
    delete null_ended_list[i];
  }
  delete [] null_ended_list;

  // Get the issuer
  char* issuer_ptr = NULL;
  if(scitoken_get_claim_string(scitoken, "iss", &issuer_ptr, &err_msg)) {
    LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failed to get issuer from token: %s\n", err_msg);
    scitoken_destroy(scitoken);
    return kCheckTokenInvalid;
  }
  string issuer(issuer_ptr);
  delete issuer_ptr;

  // Check for the appropriate scope
  Enforcer enf;
  const char* aud_list[2];
  // Get the hostname for the audience
  char hostname[1024];
  if (gethostname(hostname, 1024) != 0) {
    LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failed to get hostname");
  }
  aud_list[0] = hostname;
  aud_list[1] = NULL;
  if (!(enf = enforcer_create(issuer.c_str(), aud_list, &err_msg))) {
    LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failed to create enforcer");
    scitoken_destroy(scitoken);
    return kCheckTokenInvalid;
  }

  Acl acl;
  acl.authz = "read";
  acl.resource = issuers[issuer].c_str();
  // Set the scope appropriately
  if (enforcer_test(enf, scitoken, &acl, &err_msg)) {
    LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Failed enforcer test: %s\n", err_msg);
    enforcer_destroy(enf);
    scitoken_destroy(scitoken);
    return kCheckTokenInvalid;
  }

  scitoken_destroy(scitoken);
  enforcer_destroy(enf);
  return kCheckTokenGood;
  
}

