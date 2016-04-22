set (CVMFS_X509_HELPER_SOURCES
  x509_helper.cc
  x509_helper_base64.cc x509_helper_base64.h
  x509_helper_check.cc x509_helper_check.h
  x509_helper_dynlib.cc x509_helper_dynlib.h
  x509_helper_fetch.cc x509_helper_fetch.h
  x509_helper_globus.cc x509_helper_globus.h
  x509_helper_log.cc x509_helper_log.h
  x509_helper_req.cc x509_helper_req.h
  x509_helper_voms.cc x509_helper_voms.h)

add_executable (cvmfs_x509_helper ${CVMFS_X509_HELPER_SOURCES})
add_dependencies (cvmfs_x509_helper libvjson)
target_link_libraries (cvmfs_x509_helper vjson ${OPENSSL_LIBRARIES} dl)

install (
  TARGETS      cvmfs_x509_helper
  RUNTIME
  DESTINATION    libexec/cvmfs/authz
)
