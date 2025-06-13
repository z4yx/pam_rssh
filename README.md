# PAM-RSSH

[![Rust](https://github.com/z4yx/pam_rssh/actions/workflows/rust.yml/badge.svg)](https://github.com/z4yx/pam_rssh/actions/workflows/rust.yml)

This PAM module provides ssh-agent based authentication. The primary design goal is to avoid typing password when you `sudo` on remote servers. Instead, you can simply touch your hardware security key (e.g. Yubikey/Canokey) to fulfill user verification. The process is done by forwarding the remote authentication request to client-side ssh-agent as a signature request.

This project is developed in Rust language to minimize security flaws.

## Development Status

It's ready for production use, and has been tested on production servers for over a year. More tests and feedback are welcome.

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

Clone this repo with **a submodule**.

```
git clone --recurse-submodule https://github.com/z4yx/pam_rssh.git
cd pam_rssh
```

Then build it using Cargo.

```
cargo build --release
cp target/release/libpam_rssh.so <pam module path>
```

The `<pam module path>` is specific to certain Linux distributions.

| OS           | Destination                         |
| ------------ | ----------------------------------- |
| Arch Linux   | `/usr/lib/security/`                |
| Debian       | `/lib/x86_64-linux-gnu/security/`   |
| openSUSE     | `/lib/security/`                    |

## Config

Add the following line to `/etc/pam.d/sudo` (place it before existing rules):

```
auth sufficient libpam_rssh.so
```

Then edit sudoers with `visudo` command. Add the following line: (It makes `sudo` keep the environment variable, so this module can communicate with ssh-agent)
```
Defaults        env_keep += "SSH_AUTH_SOCK"
```


Start a ssh-agent on your client, then add your keys with `ssh-add`. 

Try to ssh to your server with forwarded agent (-A option), and make a `sudo` there. 


## Security Notice

The default public key authorization file used by pam_rssh is `~/.ssh/authorized_keys`. Typically, this file is writable to users, meaning any program executed by the user can modify it. This enables malicious programs to exploit the file and gain root privileges via `sudo` without the user's knowledge.

To mitigate this risk, you may configure the `auth_key_file` to a file only writable by root. This prevents unauthorized modifications and enhances system security. For example:

```
auth sufficient libpam_rssh.so auth_key_file=/etc/authorized_keys/${user}.keys
```

## Optional Arguments

The following arguments are supported:

- `loglevel=<off|error|warn|info|debug|trace>` Select the level of messages logged to syslog. Defaults to `warn`.
- `debug` Equivalent to `loglevel=debug`. 
- `ssh_agent_addr=<IP:port or UNIX domain address>` The address of ssh-agent. Defaults to the value of `SSH_AUTH_SOCK` environment variable, which is set by ssh automatically.
- `auth_key_file=<Path to authorized_keys>` Public keys allowed for user authentication. Defaults to `<home>/.ssh/authorized_keys`. `<home>` is read from system configuration, usually it expands to `/home/<username>`.
- `authorized_keys_command=<Path to command>` A command to generate the authorized_keys. It takes a single argument, the username of the user being authenticated. The standard output of this command will be parsed as authorized_keys. The `auth_key_file` will be ignored if you specify this argument.
- `authorized_keys_command_user=<Username>` The `authorized_keys_command` will be run as the user specified here. If this argument is omitted, the `authorized_keys_command` will be run as the user being authenticated.
- `cue` Enable device interaction prompt. When enabled, displays a message reminding the user to touch their device during authentication.
- `[cue_prompt=<message>]` Set custom prompt message for device interaction. Default: "Please touch the device". Use square brackets to include spaces in the message.

Arguments should be appended to the PAM rule. For example:

```
auth sufficient libpam_rssh.so debug authorized_keys_command=/usr/bin/sss_ssh_authorizedkeys authorized_keys_command_user=nobody cue [cue_prompt=The prompt message here]
```

## Use Variables in Arguments

Certain variables can be used in arguments. Supported formats are `$var`, `${var}` and `${var:default value}`. For example:

```
auth sufficient libpam_rssh.so auth_key_file=/data/${user}.keys
```

Variables are mapped to PAM items. Currently, the following variables are available:

- `service` - PAM_SERVICE. The service name (which identifies the PAM stack that will be used).
- `user` - PAM_USER. The username of the entity under whose identity service will be given.
- `tty` - PAM_TTY. The terminal name.
- `rhost` - PAM_RHOST. The requesting hostname.
- `ruser` - PAM_RUSER. The requesting entity.

For detailed descriptions of PAM items, read man page pam_get_item(3).
