/**
 * This file is part of the CernVM File System.
 */
#define __STDC_FORMAT_MACROS

#include "x509_helper_globus.h"
#include "x509_helper_voms.h"

int main() {

  return !GlobusLib::GetInstance()->IsValid() || !VomsLib::GetInstance()->IsValid();

}
