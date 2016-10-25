#!/bin/sh

#
# This script builds an rpm.
#

set -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 <CernVM-FS source directory> <build result location>"
  echo "This script build the rpm for the current platform."
  exit 1
fi

CVMFS_SOURCE_LOCATION="$1"
CVMFS_BUILD_LOCATION="$2"

if [ -z "$CVMFS_SOURCE_LOCATION" ]; then
  echo "CVMFS_SOURCE_LOCATION missing"
  exit 1
fi

if [ -z "$CVMFS_BUILD_LOCATION" ]; then
  echo "CVMFS_BUILD_LOCATION missing"
  exit 1
fi

SPEC_FILE="${CVMFS_SOURCE_LOCATION}/packaging/rpm/cvmfs-x509-helper.spec"

echo "preparing the build environment in ${CVMFS_BUILD_LOCATION}..."
for d in BUILD RPMS SOURCES SRPMS TMP; do
  mkdir -p ${CVMFS_BUILD_LOCATION}/${d}
done

echo "figure out version..."
VERSION=$(grep ^Version: "${SPEC_FILE}" | awk '{print $2}')
echo "  ...version ${VERSION}"

echo "create source tarball..."
cd "${CVMFS_SOURCE_LOCATION}"
git archive --prefix="cvmfs-x509-helper-${VERSION}/" \
  -o "${CVMFS_BUILD_LOCATION}/SOURCES/cvmfs-x509-helper-${VERSION}.tar.gz" \
  HEAD
ls -lah "${CVMFS_BUILD_LOCATION}/SOURCES"

echo "building RPM package..."
rpmbuild --define "%_topdir ${CVMFS_BUILD_LOCATION}"      \
         --define "%_tmppath ${CVMFS_BUILD_LOCATION}/TMP" \
         -ba "${SPEC_FILE}"
