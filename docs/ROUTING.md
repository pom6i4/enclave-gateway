# Explicit routes under endpoint policy

The `--route` starter flag and stricter transport guards described here are
unreleased source changes. The published `v0.2.0` tag is unchanged.

Route selection is configuration, not a connectivity heuristic. A failed route
never triggers another transport. Changing a route requires the administrator's
approval and an explicit configuration change.

Security mode remains a separate setting. Selecting SSH does not provide a
new Enterprise isolation guarantee. The existing Enterprise requirements remain
in force wherever that mode is configured.

## Approved SSH route

When policy permits SSH, select the agentless route:

```sh
egw config init --route ssh
egw config check
egw doctor --preflight
```

See [the SSH example](../config/enclave.ssh.example.yaml).

The controller runs the SSH client on Appliance. In POSIX Direct mode the local
Host is the controller. Target credentials and verified host keys belong on that
executing hop. They are not automatically copied from Host to a Windows Appliance.
With QGA that account is commonly SYSTEM. Verify the executing account before
provisioning keys:

```sh
egw exec @appliance 'whoami'
```

An interactive RDP user's keys belong to a different Windows profile.

The relevant settings are:

- `bastion.enabled: false` disables the RDP relay.
- `targets.app01.via: appliance` selects the SSH executor on Appliance.
- `ssh_key_path` identifies the target key on the executing hop.
- `ssh_known_hosts_path` identifies its independently verified host-key file.
- `provider.probe_host` selects an approved reachable probe destination.
- `provider.probe_port` selects its port.

An explicitly approved SSH jump host can be represented as another target:

```yaml
bastion:
  enabled: false
provider:
  type: custom
  probe_host: '10.0.10.5'
  probe_port: 22
targets:
  jump01:
    host: '10.0.10.5'
    user: operator
    os: windows
    via: appliance
    ssh_key_path: '~/.ssh/jump_ed25519'
    ssh_known_hosts_path: '~/.ssh/jump_known_hosts'
  app01:
    host: '10.0.20.11'
    user: deploy
    via: jump01
    ssh_key_path: '~/.ssh/target_ed25519'
    ssh_known_hosts_path: '~/.ssh/target_known_hosts'
```

The jump's SSH service must permit the approved forwarding destination. The
target session remains authenticated end to end by SSH. Each hop uses its own
configured key and host-key checks. Jump authentication currently requires keys;
no password-sharing fallback is provided. For this route no worker is installed
on the jump host. Invoking that host's alias explicitly executes a remote command
there under its account; restrict aliases through MCP access policy as needed.

For routine work use the same commands:

```sh
egw exec app01 'uname -a'
egw cp ./artifact.bin app01:/tmp/artifact.bin
egw cp app01:/tmp/artifact.bin ./received.bin
egw doctor --probe-targets
```

Target shell prerequisites still apply. POSIX Direct file operations require
Python 3 on the target. Root operations retain the executor's existing sudo
requirements. Network reachability alone does not authenticate a VPN provider.

`config check` reports each target's complete SSH jump chain. `status` reports
that a Bastion worker is not required. `doctor` treats RDP checks as inapplicable.
`heal` can maintain the Windows Appliance without opening RDP or staging workers.
An explicit RDP credential-refresh request is rejected. `clean` is a successful
no-op for the absent RDP spool and preserves old deployment evidence.

The following RDP-dependent operations fail explicitly in the agentless route:

- `exec @bastion`
- Direct Bastion file access
- Worker staging
- Worker pruning
- Worker attestation
- Host interactive `ssh` through `egw stdio-proxy`
- `ssh-config` for that ProxyCommand
- TCP tunnels
- SOCKS proxies
- Managed port forwards

The Host interactive SSH bridge currently depends on RDP TCP mux; it is distinct
from `egw exec` through the SSH executor. No unavailable operation starts an RDP
worker or silently bypasses the configured route. Native SSH forwarding can be
used separately when it is approved and the initiating machine has the route.

## RDP-only route

When policy permits only RDP, keep `bastion.enabled: true`. Select
`bastion.transport: rdp_vfs` and route targets through `via: bastion`.
A redirected filesystem cannot execute commands without an approved process
on Bastion.

The worker profiles are:

- `structured_only` provides fixed foreground operations through system OpenSSH.
  It requires a signed worker and an independently approved local target policy.
  It supports Files only.
- `legacy` retains the existing worker behavior under its configured security
  mode. Stream is available here when explicitly selected.

For a managed endpoint that forbids a general PowerShell worker, follow
[the foreground-profile guide](ENDPOINT-POLICY.md). Its incomplete trust pins
intentionally prevent use before administrator preparation. Its Windows/KES
qualification remains separate from portable interpreter checks.

## Shared controls and route failures

Both routes use the same Host transaction journal. They retain the existing
principal grants and secret scrubbing. File transfers verify SHA-256. A lost
acknowledgement remains indeterminate and must be reconciled before retrying.

`egw config check` and `egw capabilities` expose `automatic_route_fallback: false`.
Invalid jump chains are rejected. A configuration that disables Bastion while
still routing targets to it is rejected by route validation. Failed SSH
authentication does not select RDP. Failed RDP does not select direct SSH.
Unavailable TCP mux fails before binding a local listener.

OpenSSH's upstream references describe the forwarding behavior:

- [SSH jump hosts and stdio forwarding](https://man.openbsd.org/ssh)
- [Per-host ProxyJump configuration](https://man.openbsd.org/ssh_config#ProxyJump)
