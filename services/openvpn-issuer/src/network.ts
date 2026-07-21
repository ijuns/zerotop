export interface Ipv4Cidr {
  cidr: string;
  network: string;
  netmask: string;
  prefix: number;
  firstHost: string;
  secondHost: string;
  networkNumber: number;
  broadcastNumber: number;
}

export function parseIpv4Cidr(value: string, field: string): Ipv4Cidr {
  const match = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d|[12]\d|3[0-2])$/);
  if (!match) throw new Error(`${field} must be a canonical IPv4 CIDR.`);
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((item) => item < 0 || item > 255)) {
    throw new Error(`${field} contains an invalid IPv4 address.`);
  }
  const prefix = Number(match[5]);
  if (prefix > 30) throw new Error(`${field} must contain at least two hosts.`);
  const address = toUnsigned(
    octets[0] * 2 ** 24 + octets[1] * 2 ** 16 + octets[2] * 2 ** 8 + octets[3],
  );
  const mask = prefix === 0 ? 0 : toUnsigned(0xffffffff << (32 - prefix));
  const networkNumber = toUnsigned(address & mask);
  if (networkNumber !== address) throw new Error(`${field} must use its network address.`);
  const broadcastNumber = toUnsigned(networkNumber | toUnsigned(~mask));
  return {
    cidr: `${ipv4(networkNumber)}/${prefix}`,
    network: ipv4(networkNumber),
    netmask: ipv4(mask),
    prefix,
    firstHost: ipv4(networkNumber + 1),
    secondHost: ipv4(networkNumber + 2),
    networkNumber,
    broadcastNumber,
  };
}

export function cidrsOverlap(left: Ipv4Cidr, right: Ipv4Cidr): boolean {
  return (
    left.networkNumber <= right.broadcastNumber &&
    right.networkNumber <= left.broadcastNumber
  );
}

function ipv4(value: number): string {
  const unsigned = toUnsigned(value);
  return [24, 16, 8, 0]
    .map((shift) => (unsigned >>> shift) & 0xff)
    .join(".");
}

function toUnsigned(value: number): number {
  return value >>> 0;
}
