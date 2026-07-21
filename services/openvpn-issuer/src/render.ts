import type { CertificateMaterial, GatewayBundle, OpenVpnProfile } from "./types.ts";
import { parseIpv4Cidr } from "./network.ts";

export function renderClientProfile(
  profile: OpenVpnProfile,
  material: CertificateMaterial,
): string {
  const { host, port } = endpointParts(profile.endpoint);
  const allowed = parseIpv4Cidr(profile.allowedCidr, "allowedCidr");
  return `${[
    "client",
    "dev tun",
    "proto udp",
    `remote ${host} ${port}`,
    "nobind",
    "persist-key",
    "persist-tun",
    "auth-nocache",
    "remote-cert-tls server",
    `verify-x509-name ${material.serverCommonName} name`,
    "tls-version-min 1.2",
    "data-ciphers AES-256-GCM",
    "auth SHA256",
    `route ${allowed.network} ${allowed.netmask}`,
    "verb 3",
  ].join("\n")}
<ca>
${pem(material.caCertificate)}</ca>
<cert>
${pem(material.clientCertificate)}</cert>
<key>
${pem(material.clientPrivateKey)}</key>
<tls-crypt>
${pem(material.tlsCryptKey)}</tls-crypt>
`;
}

export function createGatewayBundle(input: {
  runId: string;
  profile: OpenVpnProfile;
  namespace: string;
  vpnCidr: string;
  material: CertificateMaterial;
}): GatewayBundle {
  const vpn = parseIpv4Cidr(input.vpnCidr, "vpnCidr");
  const allowed = parseIpv4Cidr(input.profile.allowedCidr, "allowedCidr");
  const { port } = endpointParts(input.profile.endpoint);
  const config = [
    `port ${port}`,
    "proto udp",
    "dev tun",
    "mode server",
    "tls-server",
    "topology subnet",
    `ifconfig ${vpn.firstHost} ${vpn.netmask}`,
    `ifconfig-pool ${input.profile.assignedIp} ${input.profile.assignedIp} ${vpn.netmask}`,
    `push \"route ${allowed.network} ${allowed.netmask}\"`,
    "ca /run/openvpn/ca.crt",
    "cert /run/openvpn/server.crt",
    "key /run/openvpn/server.key",
    "tls-crypt /run/openvpn/tls-crypt.key",
    "dh none",
    "ecdh-curve prime256v1",
    "verify-client-cert require",
    "remote-cert-tls client",
    `verify-x509-name ${input.material.clientCommonName} name`,
    "tls-version-min 1.2",
    "data-ciphers AES-256-GCM",
    "auth SHA256",
    "keepalive 10 60",
    "persist-key",
    "persist-tun",
    "user nobody",
    "group nogroup",
    "explicit-exit-notify 1",
    "verb 3",
  ].join("\n");
  return {
    version: 1,
    runId: input.runId,
    profileId: input.profile.profileId,
    namespace: input.namespace,
    expiresAt: input.profile.expiresAt,
    files: {
      caCertificate: input.material.caCertificate,
      serverCertificate: input.material.serverCertificate,
      serverPrivateKey: input.material.serverPrivateKey,
      tlsCryptKey: input.material.tlsCryptKey,
      serverConfig: `${config}\n`,
    },
    firewall: {
      vpnCidr: vpn.cidr,
      allowedCidr: allowed.cidr,
    },
  };
}

export function endpointParts(endpoint: string): { host: string; port: number } {
  const match = endpoint.match(/^([a-zA-Z0-9.-]+):(\d{1,5})$/);
  if (!match) throw new Error("gatewayEndpoint must be a DNS name and port.");
  const host = match[1].toLowerCase();
  const port = Number(match[2]);
  if (
    host.length > 253 ||
    !host.includes(".") ||
    host.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  ) {
    throw new Error("gatewayEndpoint is invalid.");
  }
  return { host, port };
}

function pem(value: string): string {
  return `${value.trim()}\n`;
}
