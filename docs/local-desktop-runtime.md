# Local Docker desktop runtime

`Desktop` mode runs the web application and API on Windows while Docker Desktop
creates a disposable Ubuntu or Kali browser desktop for every Lab run. The
browser never connects to a container port directly. It exchanges a one-time
ticket with the desktop gateway, and the gateway proxies the desktop HTTP and
WebSocket traffic over an internal Docker network.

## Start

```powershell
.\scripts\stop-local.ps1
.\scripts\local-dev.ps1 -Mode Desktop -WebPort 3000 -ApiPort 18080 -SkipInstall
```

Open `http://localhost:3000`, deploy a Lab with **브라우저 데스크톱**, wait for
the run status to become `ready`, then choose **워크스페이스 열기**.

The first start downloads the Ubuntu and Kali desktop images. Later runs reuse
the local image cache. Runtime logs and process metadata are stored under
`scripts/.runtime/`.

## What is real in this mode

- A separate Ubuntu or Kali GUI container is created for every run.
- A separate restricted HTTP connectivity target is created on the same
  internal network and is available from the desktop at `http://target:8080`.
- Run status is based on Docker container health, not simulated readiness.
- TTL cleanup and explicit stop remove both run containers.
- The desktop is reachable only through the loopback-bound ticket gateway.

The bundled target is a connectivity target, not a CVE-specific vulnerable
workload. AI-built and automatically validated target images replace it in the
production runtime. OpenVPN is intentionally unavailable in local Docker mode;
it requires the Kubernetes/KubeVirt runtime plane.

## Security boundary

This mode is for development on a trusted workstation. It does not expose the
desktop containers to host ports, does not use privileged containers or host
mounts, and places runs on an internal Docker network. Containers still share
the Docker Desktop Linux kernel, so kernel exploits, malware, or hostile
untrusted payloads must run on the dedicated KubeVirt/KVM infrastructure rather
than on a developer PC.
