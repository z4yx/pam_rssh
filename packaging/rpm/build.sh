#!/usr/bin/env bash
# Build an RPM package for pam-rssh.
#
# This script is intended to run inside a Fedora container where the repo is
# mounted at /work (see .github/workflows/rpm-release.yml), but it also works
# on a Fedora/RHEL host with the required build tools installed:
#
#   dnf install rpm-build cargo rustc openssl-devel pam-devel pkgconfig \
#             openssh-clients make gcc diffutils tar gzip clang-devel
#
# It vendors all Cargo dependencies into the source tarball so that rpmbuild
# can run fully offline (no network access to crates.io during the build).
#
# Run from the repository root:
#   ./packaging/rpm/build.sh
# The resulting .rpm files are written to ./rpm-artifacts/.

set -euo pipefail

# --- Configuration -----------------------------------------------------------
SPEC="$(cd "$(dirname "$0")" && pwd)/pam-rssh.spec"
TOPLEVEL="$(rpm --eval '%{_topdir}')"          # e.g. $HOME/rpmbuild on Fedora

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [ -z "$VERSION" ]; then
    echo "ERROR: cannot determine version from Cargo.toml" >&2
    exit 1
fi
echo "==> Building pam-rssh-${VERSION}"

# --- Vendor all Cargo dependencies -------------------------------------------
echo "==> Vendoring Cargo dependencies"
cargo vendor vendor
mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

# --- Prepare the source tarball (including the vendored deps) ----------------
echo "==> Preparing source tarball"
rm -rf /tmp/src
mkdir -p /tmp/src
cp -a . "/tmp/src/pam-rssh-${VERSION}"
rm -rf "/tmp/src/pam-rssh-${VERSION}/target" \
       "/tmp/src/pam-rssh-${VERSION}/debian" \
       "/tmp/src/pam-rssh-${VERSION}/.git" \
       "/tmp/src/pam-rssh-${VERSION}/.github" \
       "/tmp/src/pam-rssh-${VERSION}/.vscode" \
       "/tmp/src/pam-rssh-${VERSION}/rpm-artifacts"

mkdir -p "${TOPLEVEL}/SOURCES"
tar -czf "${TOPLEVEL}/SOURCES/pam-rssh-${VERSION}.tar.gz" \
    -C /tmp/src "pam-rssh-${VERSION}"

# --- Build the RPM -----------------------------------------------------------
echo "==> Building RPM"
rpmbuild -bb "${SPEC}"

echo "==> Built RPMs:"
find "${TOPLEVEL}/RPMS" -name '*.rpm' -print

# --- Copy artifacts back into the repository ----------------------------------
mkdir -p rpm-artifacts
cp "${TOPLEVEL}"/RPMS/*/*.rpm rpm-artifacts/
echo "==> RPMs copied to ./rpm-artifacts/"
