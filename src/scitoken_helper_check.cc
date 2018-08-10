/**
 * This file is part of the CernVM File System.
 */
#include "scitoken_helper_check.h"
#include "x509_helper_log.h"

#include <boost/python.hpp>

#include <sys/types.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace std;  // NOLINT

boost::python::object g_validation_function;



static std::string
handle_pyerror()
{
    PyObject *exc,*val,*tb;
    boost::python::object formatted_list, formatted;
    PyErr_Fetch(&exc,&val,&tb);
    boost::python::handle<> hexc(exc), hval(boost::python::allow_null(val)), htb(boost::python::allow_null(tb));
    boost::python::object traceback(boost::python::import("traceback"));
    boost::python::object format_exception(traceback.attr("format_exception"));
    formatted_list = format_exception(hexc,hval,htb);
    formatted = boost::python::str("\n").join(formatted_list);
    return boost::python::extract<std::string>(formatted);
}


__attribute__ ((visibility ("default")))
StatusSciTokenValidation CheckSciToken(const string &membership, FILE *fp_token) {

  if (!Py_IsInitialized())
  {
    char pname[] = "cvmfs_scitokens_helper";
    Py_SetProgramName(pname);
    Py_InitializeEx(0);

    try {
      boost::python::object helper_module = boost::python::import("cvmfs_scitokens_helper");
      g_validation_function = helper_module.attr("check_token");
    } catch (boost::python::error_already_set &) {
      LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr,
               "Failed to initialize cvmfs_scitokens_helper python module: %s\n", handle_pyerror().c_str());

      // TODO: Log failure -- use handle_pyerror above
      return kCheckTokenInvalid;
    }
  } else if (g_validation_function.ptr() == Py_None) {
    // TODO: Log failure.
    return kCheckTokenInvalid;
  }

  bool result = false;
  try {
    PyObject *fp_pyobj = PyFile_FromFile(fp_token, "token_handle", "r", fclose);
    if (!fp_pyobj) {
      // TODO: Log failure
      return kCheckTokenInvalid;
    }
    boost::python::object fp_obj(boost::python::handle<>(fp_pyobj));

    boost::python::object membership_obj(membership);

    boost::python::object result_obj = g_validation_function(membership_obj, fp_obj);
  } catch (boost::python::error_already_set &) {
    // TODO: Log failure.
  }
  
  // At this point, fp_token points to the token file
  // Membership should be a list of valid issuers
  
  return result ? kCheckTokenGood : kCheckTokenInvalid;
  
}

