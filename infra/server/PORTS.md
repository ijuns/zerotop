# Network and firewall matrix

Keep all node-to-node traffic on a private cluster network. Because Cilium, Longhorn, KubeVirt and Kubernetes can add version-specific health and migration flows, the robust policy is to allow bidirectional traffic only among the declared cluster-node addresses on that private network, then deny every other source. If policy requires individual ports, validate the matrix below against every pinned component during each upgrade.

| Source | Destination | Protocol/port | Purpose | Exposure |
|---|---|---:|---|---|
| Ansible control host | All nodes | TCP 22 | SSH bootstrap and maintenance | Management CIDR only |
| All RKE2 nodes | HA VIP / server nodes | TCP 9345 | RKE2 registration/supervisor | Private cluster only |
| All RKE2 nodes and administrators | HA VIP / server nodes | TCP 6443 | Kubernetes API | Nodes plus management CIDR only |
| RKE2 servers | RKE2 servers | TCP 2379-2381 | embedded-etcd client, peer, metrics | Server private IPs only |
| All RKE2 nodes | All RKE2 nodes | TCP 10250 | kubelet API | Private cluster only |
| RKE2 servers | RKE2 servers | TCP 10257, 10259 | controller-manager and scheduler | Server private IPs only |
| All RKE2 nodes | All RKE2 nodes | UDP 8472 | Cilium VXLAN overlay | Private cluster only; never public |
| All RKE2 nodes | All RKE2 nodes | UDP 51871 | Cilium WireGuard encryption | Private cluster only |
| All RKE2 nodes | All RKE2 nodes | TCP 4240 | Cilium health checks | Private cluster only |
| KubeVirt nodes | KubeVirt nodes | TCP 49152-49215 | VM live-migration data range | Private cluster only |
| Longhorn nodes | Longhorn nodes | TCP 9500-9504 and pod-network flows | Manager, engine and replica control | Private cluster only |
| RKE2 servers | RKE2 servers | IP protocol 112 | Keepalived VRRP | Same private L2 segment only |
| HAProxy on server nodes | Server-node NodePorts | TCP 30080, 30443 | RKE2 Traefik HTTP/HTTPS backends using PROXY v2 | Server private IPs only |
| Authorized clients or upstream load balancer | HA VIP | TCP 80, 443 | Public application ingress | Restrict 80 to redirect/ACME needs |
| Authorized lab clients | Per-run OpenVPN load-balancer address | UDP 1194 | One isolated VPN data plane per run | Public only while that run is active |
| Nodes and pods | Approved DNS resolvers | UDP/TCP 53 | Name resolution | Approved resolvers only |
| Nodes | Approved NTP sources | UDP 123 | Time synchronization | Approved time sources only |
| Nodes/controllers | Approved registries, release mirrors, S3, secret backend | TCP 443 | Images, pinned artifacts, backups, secrets | Egress allowlist/proxy |

HAProxy binds the private VIP and forwards ports 80/443 to fixed Traefik NodePorts. Do not publish those NodePorts directly; the host firewall or upstream ACL must accept them only from the server-node addresses. Every OpenVPN-enabled run creates a separate UDP LoadBalancer and DNS record outside the application VIP. Enforce address quotas, deletion alerts, and an upstream source/rate policy; never replace these with one gateway that can route to all run namespaces.

The runtime-plane default-deny policy does not replace perimeter controls. Learner namespaces must never reach node management addresses, the Kubernetes API, identity services, databases, cloud metadata, or other learners' namespaces.
