# Ansible Collection - agnosticd.showroom

Collection for deploying and running Showroom. Includes an OpenShift workload role (Helm-based) and a standalone host role.

## Contents

- `ocp4_workload_showroom`: Deploys Showroom to OpenShift via the `showroom-single-pod` Helm chart. Supports content-only, terminal (Wetty or in-cluster terminal pod), and multi-user modes. See `roles/ocp4_workload_showroom/README.adoc`.
- `showroom`: Installs and runs Showroom on a host using Traefik; optional ACME TLS via ZeroSSL or Let’s Encrypt. See `roles/showroom/README.adoc`.

## Install

```bash
ansible-galaxy collection install git+https://github.com/agnosticd/showroom.git
```

Dependencies are declared in `galaxy.yml` (e.g., `kubernetes.core ">=2.4.0,<3.0.0"`). If your environment relies on AgnosticD plugins (for example `agnosticd_user_info` / `agnosticd_user_data`), ensure the appropriate AgnosticD collection is installed in your environment.

## Quickstart

Deploy to OpenShift:
```yaml
- hosts: localhost
  roles:
    - role: agnosticd.showroom.ocp4_workload_showroom
```

Run on a host:
```yaml
- hosts: showroom_host
  roles:
    - role: agnosticd.showroom.showroom
```

## Requirements

- ansible-core >= 2.14
- OpenShift 4.10+ for the OpenShift workload role

## License

GPL-3.0-or-later
