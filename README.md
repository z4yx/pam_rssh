# PAM-RSSH

[![Rust](https://github.com/z4yx/pam_rssh/actions/workflows/rust.yml/badge.svg)](https://github.com/z4yx/pam_rssh/actions/workflows/rust.yml)

This PAM module provides ssh-agent based authentication. The primary design goal is to avoid typing password when you `sudo` on remote servers. Instead, you can simply touch your hardware security key (e.g. Yubikey/Canokey) to fulfill user verification. The process is done by forwarding the remote authentication request to client-side ssh-agent as a signature request.

This project is developed in Rust language to minimize security flaws.

## Development Status

It's a preliminary version now. Test and feedback are needed.

Currently supported SSH public key types:
- RSA (with SHA256 digest)
- DSA
- ECDSA 256/384/521
- ECDSA-SK (FIDO2/U2F)
- ED25519
- ED25519-SK (FIDO2)

## Build and Install

Prerequisites:

- OpenSSL (>=1.1.1) 
- libpam
- Rust (with Cargo)

Clone this repo and **two submodules**.

```
git clone --recurse-submodule https://github.com/z4yx/pam_rssh.git
cd pam_rssh
```

Then build it using Cargo.

```
cargo build --release
cp target/release/libpam_rssh.so /usr/local/lib/
```

## Config

Add the following line to `/etc/pam.d/sudo` (place it before existing rules):

```
auth sufficient /usr/local/lib/libpam_rssh.so
```

Then edit sudoers with `visudo` command. Add the following line: (It makes `sudo` keep the environment variable, so this module can communicate with ssh-agent)
```
Defaults        env_keep += "SSH_AUTH_SOCK"
```


Start a ssh-agent on your client, then add your keys with `ssh-add`. 

Try to ssh to your server with forwarded agent (-A option), and make a `sudo` there. 

## Arguments

The following arguments are supported:

- `loglevel=<off|error|warn|info|debug|trace>` Select the level of messages logged to syslog. Defaults to `warn`.
- `debug` Equivalent to `loglevel=debug`. 
- `ssh_agent_addr=<IP:port or UNIX domain address>` The address of ssh-agent. Defaults to the value of `SSH_AUTH_SOCK` environment variable, which is set by ssh automatically.
- `auth_key_file=<Path to authorized_keys>` Public keys allowed for user authentication. Defaults to `$HOME/.ssh/authorized_keys`. Usually `$HOME` expands to `/home/<username>`.

Arguments should be appended to the PAM rule. For example, `auth sufficient /usr/local/lib/libpam_rssh.so debug`.
