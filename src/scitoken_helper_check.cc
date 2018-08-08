/**
 * This file is part of the CernVM File System.
 */
#include "scitoken_helper_check.h"

#include <alloca.h>
#include <sys/types.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace std;  // NOLINT

StatusSciTokenValidation CheckSciToken(const string &membership, FILE *fp_token) {
  
  // At this point, fp_token points to the token file
  // Membership should be a list of valid issuers
  
  return kCheckTokenGood;
  
}

