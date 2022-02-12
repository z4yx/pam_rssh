# PAM-RSSH

This PAM module provides ssh-agent based authentication. The primary design goal is to avoid typing password when you `sudo` on remote servers. Instead, you can simply touch your hardware security key (e.g. Yubikey) to fulfill user verification. The process is done by forwarding the remote authentication request to client-side ssh-agent as a signature request.

## Build and Install

Prerequisites:

- OpenSSL (>=1.1.1) 
- libpam
- Rust (with Cargo)

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
- `auth_key_file=<Path to authorized_keys>` Public keys allowed for user authentication. Defaults to `/home/<username>/.ssh/authorized_keys`.

Arguments should be appended to the PAM rule. For example, `auth sufficient /usr/local/lib/libpam_rssh.so debug`.
