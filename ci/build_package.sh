#!/bin/sh

#
# This script builds a package that fits the current platform.
#

set -e

get_package_type() {
  which dpkg > /dev/null 2>&1 && echo "deb" && return 0
  which rpm  > /dev/null 2>&1 && echo "rpm" && return 0
  return 1
}

if [ $# -lt 2 ]; then
  echo "Usage: $0 <CernVM-FS source directory> <build result location>"
  echo "This script builds the package for the current platform."
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

$(dirname $0)/$(get_package_type).sh "$CVMFS_SOURCE_LOCATION" "$CVMFS_BUILD_LOCATION"
