set (CVMFS_X509_HELPER_SOURCES
  x509_helper.cc
  x509_helper_base64.cc x509_helper_base64.h
  x509_helper_check.cc x509_helper_check.h
  x509_helper_dynlib.cc x509_helper_dynlib.h
  x509_helper_fetch.cc x509_helper_fetch.h
  x509_helper_globus.cc x509_helper_globus.h
  x509_helper_log.cc x509_helper_log.h
  x509_helper_req.cc x509_helper_req.h
  x509_helper_voms.cc x509_helper_voms.h
  helper_utils.cc helper_utils.h
  scitoken_helper_fetch.cc scitoken_helper_fetch.cc
  scitoken_helper_loader.cc scitoken_helper_loader.h)

set (LIBCVMFS_X509_HELPER_SOURCES
  scitoken_helper_check.cc scitoken_helper_check.h)

set (CVMFS_X509_VALIDATOR_SOURCES
  x509_validator.cc
  x509_helper_globus.cc x509_helper_globus.h
  x509_helper_log.cc x509_helper_log.h
  x509_helper_dynlib.cc x509_helper_dynlib.h
  x509_helper_voms.cc x509_helper_voms.h)

add_library (libcvmfs_scitoken_helper MODULE ${LIBCVMFS_X509_HELPER_SOURCES})
set_target_properties (libcvmfs_scitoken_helper PROPERTIES OUTPUT_NAME cvmfs_scitoken_helper)

add_executable (cvmfs_x509_helper ${CVMFS_X509_HELPER_SOURCES})
add_executable (cvmfs_scitoken_helper ${CVMFS_X509_HELPER_SOURCES})
add_executable (cvmfs_x509_validator ${CVMFS_X509_VALIDATOR_SOURCES})
add_dependencies (cvmfs_x509_helper libvjson)
add_dependencies (cvmfs_scitoken_helper libvjson)
target_link_libraries (cvmfs_x509_helper vjson ${OPENSSL_LIBRARIES} dl)
target_link_libraries (cvmfs_scitoken_helper vjson ${OPENSSL_LIBRARIES} dl)
target_link_libraries (cvmfs_x509_validator dl)

install (
  TARGETS      cvmfs_x509_helper cvmfs_x509_validator cvmfs_scitoken_helper
  RUNTIME
  DESTINATION    libexec/cvmfs/authz
  LIBRARY
  DESTINATION    lib
)


