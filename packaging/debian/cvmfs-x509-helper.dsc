# created by ../../ci/update-debdsc.sh, do not edit by hand
3.0 (native)
Source: cvmfs-x509-helper
Maintainer: Jakob Blomer <jblomer@cern.ch>
Section: utils
Priority: extra
Standards-Version: 3.9.3.1
Build-Depends: debhelper (>= 9), cmake, libglobus-common-dev, libglobus-gsi-callback-dev, libglobus-gsi-cert-utils-dev, libglobus-gsi-credential-dev, libssl-dev, pkg-config, voms-dev, uuid-dev
Homepage: http://cernvm.cern.ch/portal/filesystem

Package: cvmfs-x509-helper
Architecture: i386 amd64
Depends: ${shlibs:Depends}, cvmfs, libglobus-common0, libglobus-gsi-callback0, libglobus-gsi-cert-utils0, libglobus-gsi-credential1, libvomsapi1
Description: CernVM File System X509 authz helper
Files:
  ffffffffffffffffffffffffffffffff 99999 cvmfs-x509-helper-1.0.1.tar.gz