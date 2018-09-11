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

  LogAuthz(kLogAuthzDebug | kLogAuthzSyslog | kLogAuthzSyslogErr, "Checking scitoken");
  fprintf(stderr, "Checking scitoken\n");
  if (!Py_IsInitialized())
  {
    char pname[] = "cvmfs_scitokens_helper";
    Py_SetProgramName(pname);
    Py_InitializeEx(0);

    try {
      boost::python::object helper_module = boost::python::import("cvmfs_scitokens_helper");
      g_validation_function = helper_module.attr("check_token");
    } catch (boost::python::error_already_set &) {
      fprintf(stderr, "Failed to initialize cvmfs_scitokens_helper python module: %s\n", handle_pyerror().c_str());

      // TODO: Log failure -- use handle_pyerror above
      return kCheckTokenInvalid;
    }
  } else if (g_validation_function.ptr() == Py_None) {
    // TODO: Log failure.
    fprintf(stderr, "Failed to find cvmfs_scitokens_helper module and check_token attribute: %s\n", handle_pyerror().c_str());
    return kCheckTokenInvalid;
  }

  bool result = false;
  try {
    char fname[] = "token_handle";
    char mode[] = "r";
    PyObject *fp_pyobj = PyFile_FromFile(fp_token, fname, mode, fclose);
    if (!fp_pyobj) {
      // TODO: Log failure
      fprintf(stderr, "Failed to initialize file handle to token: %s\n", handle_pyerror().c_str());
      return kCheckTokenInvalid;
    }
    
    boost::python::handle<> fp_handle(fp_pyobj);
    
    boost::python::object fp_obj(fp_handle);

    boost::python::object membership_obj(membership);

    boost::python::object result_obj = g_validation_function(membership_obj, fp_obj);
    result = boost::python::extract<bool>(result_obj);
  } catch (boost::python::error_already_set &) {
    fprintf(stderr, "Failed to call validation function: %s\n", handle_pyerror().c_str());
  }
  
  // At this point, fp_token points to the token file
  // Membership should be a list of valid issuers
  
  return result ? kCheckTokenGood : kCheckTokenInvalid;
  
}

