
#include "scitoken_helper_check.h"


class SciTokenLib;

class SciTokenLibDestroyer {
  friend class SciTokenLib;

public:
  SciTokenLibDestroyer() {m_instance = NULL;}
  ~SciTokenLibDestroyer();

private:
  void set(SciTokenLib *instance) {m_instance = instance;}

  SciTokenLib *m_instance;
};

class SciTokenLib {
  friend class SciTokenLibDestroyer;

public:
  ~SciTokenLib() {Close();}

  static CheckSciToken_t GetInstance() {
    if (!g_instance) {
      g_instance = new SciTokenLib();
      g_destroyer.set(g_instance);
    }

    return g_instance->m_check_scitoken;
  }

private:
  SciTokenLib() : m_scitoken_check_handle(NULL), m_check_scitoken(NULL)
  {Load();}

  SciTokenLib(const SciTokenLib&);
  void Close();
  void Load();

  // Various library and symbol handles.
  void *m_scitoken_check_handle;
  CheckSciToken_t m_check_scitoken;

  // Singleton instances
  static SciTokenLib *g_instance;
  static SciTokenLibDestroyer g_destroyer;
};
