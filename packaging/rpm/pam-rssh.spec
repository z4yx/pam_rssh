# RPM spec for pam-rssh
#
# The build is fully offline: the source tarball (Source0) must already
# contain the vendored Cargo dependencies. The `packaging/rpm/build.sh`
# script (and .github/workflows/rpm-release.yml) takes care of that.

Name:           pam-rssh
Version:        1.2.2
Release:        1%{?dist}
Summary:        PAM module for SSH-agent based authentication

License:        MIT
URL:            https://github.com/z4yx/pam_rssh
Source0:        %{name}-%{version}.tar.gz

# --- Rust toolchain ---
BuildRequires:  cargo
BuildRequires:  rustc
# --- Native build tools ---
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  diffutils
# --- Native library headers (needed by openssl-sys / pam-bindings) ---
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
# --- libclang (needed by libsyslog-sys to generate FFI bindings via bindgen) ---
BuildRequires:  clang-devel
# --- Needed by the test-suite (ssh-keygen / ssh-agent / ssh-add) ---
BuildRequires:  openssh-clients

# --- Runtime dependencies ---
Requires:       pam
Requires:       openssl-libs

%description
This PAM module provides ssh-agent based authentication. It allows
authentication using SSH keys forwarded through ssh-agent instead of
typing passwords. This is particularly useful for remote sudo access
with hardware security keys like Yubikey or Canokey.

Supported SSH key types:
- RSA (with SHA256 digest)
- DSA
- ECDSA 256/384/521
- ECDSA-SK (FIDO2/U2F)
- ED25519
- ED25519-SK (FIDO2)

%prep
%autosetup -n pam-rssh-%{version}

%build
# Dependencies are vendored into the source tarball, so the build runs
# fully offline (no access to crates.io required).
cargo build --release --offline

%install
install -D -m 0755 target/release/libpam_rssh.so \
    %{buildroot}%{_libdir}/security/libpam_rssh.so

%check
# The unit tests need an ssh-agent preloaded with the supported key types.
export SSH_AUTH_SOCK=/tmp/ssh-agent.sock
export USER=$(whoami)
test -f $HOME/.ssh/id_ecdsa521 || ssh-keygen -N "" -t ecdsa -b 521 -f $HOME/.ssh/id_ecdsa521
test -f $HOME/.ssh/id_ecdsa384 || ssh-keygen -N "" -t ecdsa -b 384 -f $HOME/.ssh/id_ecdsa384
test -f $HOME/.ssh/id_ecdsa256 || ssh-keygen -N "" -t ecdsa -b 256 -f $HOME/.ssh/id_ecdsa256
test -f $HOME/.ssh/id_ed25519 || ssh-keygen -N "" -t ed25519 -f $HOME/.ssh/id_ed25519
test -f $HOME/.ssh/id_rsa || ssh-keygen -N "" -t rsa -f $HOME/.ssh/id_rsa
eval "$(ssh-agent -a "$SSH_AUTH_SOCK")"
ssh-add $HOME/.ssh/id_ecdsa521
ssh-add $HOME/.ssh/id_ecdsa384
ssh-add $HOME/.ssh/id_ecdsa256
ssh-add $HOME/.ssh/id_ed25519
ssh-add $HOME/.ssh/id_rsa
cp $HOME/.ssh/id_rsa.pub $HOME/.ssh/authorized_keys
cargo test --release --offline
ssh-agent -k

%files
%{_libdir}/security/libpam_rssh.so
%doc README.md
%license LICENSE

%changelog
* Thu Aug 27 2026 Yuxiang Zhang <z4yx@users.noreply.github.com> - 1.2.2-1
- Replace syslog crate with libsyslog (native system syslog)
- Add RPM packages for more distributions (Fedora, RHEL-compatible Rocky Linux)

* Wed Aug 26 2026 Yuxiang Zhang <z4yx@users.noreply.github.com> - 1.2.0-1
- Initial RPM package
