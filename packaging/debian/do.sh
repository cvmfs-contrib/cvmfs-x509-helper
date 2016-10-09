#!/bin/sh

set -e

#
# This script is not called by the CI system! It is supposed to be used for
# package creation debugging and as a blue print for CI configuration.
#

usage() {
  echo "Sample script that builds the cvmfs-x509-helper debian package from source"
  echo "Usage: $0 <work dir> <source tree root>"
  exit 1
}

if [ $# -ne 2 ]; then
  usage
fi

workdir=$1
srctree=$(readlink --canonicalize $2)

if [ "$(ls -A $workdir 2>/dev/null)" != "" ]; then
  echo "$workdir must be empty"
  exit 2
fi

echo -n "creating workspace in $workdir... "
mkdir ${workdir}/tmp ${workdir}/src ${workdir}/result
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
eval `sed -n 's/set (CVMFS-X509-Helper_VERSION_\([^ ]*\) \([0-9]*\)).*/\1=\2/p' ${srctree}/CMakeLists.txt`
upstream_version="$MAJOR.$MINOR.$PATCH"
echo "done: $upstream_version"

echo "building..."
cd ${workdir}/src/cvmfs-x509-helper
dch -v $upstream_version -M "bumped upstream version number"

cd debian
pdebuild --buildresult ${workdir}/result -- --save-after-exec --debug
