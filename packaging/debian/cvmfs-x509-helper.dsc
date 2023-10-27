# created by ../../ci/obsupdate-deb.sh, do not edit by hand
Debtransform-Tar: cvmfs-x509-helper-2.4.tar.gz
Format: 1.0
Version: 2.4.1-1
Binary: cvmfs-x509-helper
Source: cvmfs-x509-helper
Maintainer: Jakob Blomer <jblomer@cern.ch>
Section: utils
Priority: extra
Standards-Version: 3.9.3.1
Build-Depends: debhelper (>= 9), cmake, libglobus-common-dev, libglobus-gsi-callback-dev, libglobus-gsi-cert-utils-dev, libglobus-gsi-credential-dev, libssl-dev, libscitokens-dev, pkg-config, voms-dev, uuid-dev
Homepage: http://cernvm.cern.ch/portal/filesystem

Package: cvmfs-x509-helper
Architecture: i386 amd64
Depends: ${shlibs:Depends}, cvmfs (>= 2.6.0), libglobus-common0, libglobus-gsi-callback0, libglobus-gsi-cert-utils0, libglobus-gsi-credential1, libvomsapi1 | libvomsapi1v5, libscitokens0
Description: CernVM File System X509 authz helper
Files:
  ffffffffffffffffffffffffffffffff 99999 file1
  ffffffffffffffffffffffffffffffff 99999 file2
