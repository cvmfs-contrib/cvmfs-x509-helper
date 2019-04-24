

#include "x509_helper_dynlib.h"
#include "scitoken_helper_loader.h"

SciTokenLib *SciTokenLib::g_instance = NULL;
SciTokenLibDestroyer SciTokenLib::g_destroyer;


SciTokenLibDestroyer::~SciTokenLibDestroyer() {
  if (m_instance) delete m_instance;
}


/**
 * Load SciToken validation library.
 * If successful, sets the global symbol appropriately.
 */
void
SciTokenLib::Load() {
  if (!OpenDynLib(&m_scitoken_check_handle,
                  "libcvmfs_scitoken_helper.so",
                  "SciToken checker")) {return;}

  if (!LoadSymbol(m_scitoken_check_handle, &m_check_scitoken, "CheckSciToken"))
  {
    printf("Failed to load CheckSciToken symbol\n");
  }
}     


void
SciTokenLib::Close() {
  CloseDynLib(&m_scitoken_check_handle, "SciToken checker");
}
