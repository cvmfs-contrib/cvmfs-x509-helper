#!/bin/sh

#
# This script builds the debian package
#

set -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 <cvmfs-x509-helper source directory> <build result location>"
  echo "This script builds the deb for the current platform."
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

workdir="$CVMFS_BUILD_LOCATION"
srctree=$(readlink --canonicalize "$CVMFS_SOURCE_LOCATION")

if [ "$(ls -A $workdir 2>/dev/null)" != "" ]; then
  echo "$workdir must be empty"
  exit 2
fi

echo -n "creating workspace in $workdir... "
mkdir ${workdir}/tmp ${workdir}/src
echo "done"

echo -n "copying source tree to $workdir/tmp... "
cp -R $srctree/* ${workdir}/tmp
echo "done"

echo -n "initializing build environment... "
mkdir ${workdir}/src/cvmfs-x509-helper
cp -R $srctree/* ${workdir}/src/cvmfs-x509-helper
mkdir ${workdir}/src/cvmfs-x509-helper/debian
cp -R ${workdir}/tmp/packaging/debian/* ${workdir}/src/cvmfs-x509-helper/debian
echo "done"

echo -n "figuring out version number... "
specfile="$srctree/packaging/rpm/cvmfs-x509-helper.spec"
upstream_version="$(grep ^Version: $specfile | awk '{print $2}').$(grep '%define release_prefix' $specfile | awk '{print $3}' | cut -d% -f1)"
echo "done: $upstream_version"

echo "building..."
cd ${workdir}/src/cvmfs-x509-helper
dch -v $upstream_version -M "bumped upstream version number"
DEB_BUILD_OPTIONS=parallel=$(nproc) debuild -us -uc # -us -uc == skip signing
