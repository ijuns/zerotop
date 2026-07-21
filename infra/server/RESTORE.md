# RKE2 and storage recovery runbook

This procedure is intentionally operator-driven. Test it in an isolated recovery environment at least quarterly. An etcd snapshot restores Kubernetes state, not Longhorn volume contents or external PostgreSQL, Redis, Elasticsearch, identity, object-storage, or secret-manager data.

## 1. Declare and isolate the incident

1. Stop application writes and disable public ingress at the upstream load balancer or firewall.
2. Record the incident time, affected nodes, RKE2 version, snapshot names, Longhorn backup state, and external database recovery point.
3. Preserve logs and disk images needed for investigation. Do not overwrite the only evidence with an immediate rebuild.
4. Select a known-good etcd snapshot from the off-node S3 target and verify object version, encryption controls, retention status, and access audit trail.
5. Retrieve the original encrypted vault through the approved break-glass process. The original RKE2 token may be required to decrypt bootstrap data.

## 2. Restore embedded etcd

Use the same pinned RKE2 version that created the selected snapshot. On all server nodes:

```bash
sudo systemctl stop rke2-server
```

On the first inventory server only, restore the selected snapshot. Use the exact snapshot name shown by `rke2 etcd-snapshot list --s3`; do not paste an unreviewed path from an incident message.

```bash
sudo rke2 etcd-snapshot list --s3
sudo rke2 server --cluster-reset --cluster-reset-restore-path=SELECTED_SNAPSHOT --etcd-s3
sudo systemctl start rke2-server
sudo kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get --raw=/readyz
```

Do not start the remaining servers until the first API and embedded-etcd member are healthy. On each remaining server, move its stale database aside to a host-local quarantine path, then rejoin it using the protected configuration already managed by Ansible:

```bash
sudo systemctl stop rke2-server
sudo mv /var/lib/rancher/rke2/server/db /var/lib/rancher/rke2/server/db.pre-recovery
sudo systemctl start rke2-server
```

If a quarantine path already exists, stop and choose a unique, explicitly reviewed path. Do not delete the old database until recovery is signed off and evidence-retention requirements are met.

Wait for all three nodes and control-plane pods:

```bash
sudo kubectl --kubeconfig /root/.kube/config wait node --all --for=condition=Ready --timeout=600s
sudo kubectl --kubeconfig /root/.kube/config get pods --all-namespaces
```

## 3. Restore persistent workloads

1. Confirm External Secrets has reconciled the Longhorn backup credential and application Secrets from the approved remote store.
2. Confirm the Longhorn backup target points to the intended recovery environment, not production by accident.
3. Restore required Longhorn volumes from backups or disaster-recovery volumes, preserving the original volume and backup identifiers in the incident record.
4. Restore external PostgreSQL, Elasticsearch, object storage, Keycloak, and other managed data services through their own runbooks to a mutually consistent recovery point.
5. Rebind restored PVCs only after validating filesystem integrity and application-level consistency.

Do not assume etcd snapshot time and volume backup time are identical. Prefer a documented application-consistent checkpoint; otherwise involve application owners before writes resume.

## 4. Validate and reopen

Run the complete verification playbook:

```bash
cd infra/server
ansible-playbook verify.yml --ask-vault-pass -e @vars/vault.yml
```

Then verify:

- Cilium policy and encrypted node connectivity;
- KubeVirt/CDI availability and `devices.kubevirt.io/kvm` on every workload node;
- Longhorn replicas, backup target, restored volume health, and the default StorageClass;
- cert-manager certificates and External Secrets readiness;
- platform OIDC login, organization authorization, lab start/stop, desktop ticket exchange, one isolated noVNC session, and one isolated OpenVPN session;
- ranking and grading data against the selected database recovery point;
- audit-log continuity and incident-time credential rotation.

Re-enable external traffic in stages. Keep the quarantined node data and recovery records until security and service owners approve disposal.
