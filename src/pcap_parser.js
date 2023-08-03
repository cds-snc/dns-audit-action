const fs = require("fs");
const ip = require("ip");

const ethernetHeader = (buffer) => {
  return {
    destination: buffer.subarray(0, 6).toString("hex").match(/.{2}/g).join(":"),
    source: buffer.subarray(6, 12).toString("hex").match(/.{2}/g).join(":"),
    ethertype: buffer.readUInt16BE(12),
  };
};

const tcpHeader = (buffer) => {
  return {
    type: "TCP",
    sourcePort: buffer.readUInt16BE(0),
    destinationPort: buffer.readUInt16BE(2),
    sequenceNumber: buffer.readUInt32BE(4),
    acknowledgmentNumber: buffer.readUInt32BE(8),
    dataOffset: (buffer.readUInt8(12) >> 4) & 0x0f,
    flags: buffer.readUInt8(13),
    windowSize: buffer.readUInt16BE(14),
    checksum: buffer.readUInt16BE(16),
    urgentPointer: buffer.readUInt16BE(18),
  };
};

const udpHeader = (buffer) => {
  return {
    type: "UDP",
    sourcePort: buffer.readUInt16BE(0),
    destinationPort: buffer.readUInt16BE(2),
    length: buffer.readUInt16BE(4),
    checksum: buffer.readUInt16BE(6),
  };
};

function parseDnsQuery(payload) {
  const flags = payload.readUInt16BE(2); // Flags field is at offset 2
  const isResponse = (flags & 0x8000) !== 0; // Most significant bit indicates response
  const opcode = (flags >> 11) & 0x0f; // Opcode is the 4 bits following the response bit
  const authoritativeAnswer = (flags & 0x0400) !== 0;
  const truncated = (flags & 0x0200) !== 0;
  const recursionDesired = (flags & 0x0100) !== 0;
  const recursionAvailable = (flags & 0x0080) !== 0;
  const responseCode = flags & 0x000f; // 4 bits for the response code

  let queryName = "";
  let offset = 12; // Start of the query name

  while (payload[offset] !== 0) {
    const labelLength = payload[offset];
    queryName +=
      payload.slice(offset + 1, offset + 1 + labelLength).toString("utf8") +
      ".";
    offset += labelLength + 1;
  }

  const queryType = payload.readUInt16BE(offset + 1); // Query type is 2 bytes after the query name
  const queryClass = payload.readUInt16BE(offset + 3); // Query class is 2 bytes after the query type

  // Mapping of DNS query types to their names
  const queryTypeNames = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    108: "EUI48",
    109: "EUI64",
    13: "HINFO",
    55: "HIP",
    65: "HTTPS",
    45: "IPSECKEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    12: "PTR",
    46: "RRSIG",
    17: "RP",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    64: "SVCB",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",
    63: "ZONEMD",
  };

  const queryTypeName = queryTypeNames[queryType] || queryType.toString();

  return {
    isResponse,
    opcode,
    authoritativeAnswer,
    truncated,
    recursionDesired,
    recursionAvailable,
    responseCode,
    queryName,
    queryType: queryTypeName,
    queryClass,
  };
}

function parsePcapFile(filename) {
  const pcapData = fs.readFileSync(filename);
  const packets = [];

  let offset = 24; // Skip the PCAP global header

  while (offset < pcapData.length) {
    const tsSec = pcapData.readUInt32LE(offset);
    const tsUsec = pcapData.readUInt32LE(offset + 4);
    const inclLen = pcapData.readUInt32LE(offset + 8);
    const origLen = pcapData.readUInt32LE(offset + 12);
    const packetData = pcapData.subarray(offset + 16, offset + 16 + inclLen);

    const ethHeader = ethernetHeader(packetData);

    let transportHeader = null;
    let parsedDnsQuery = null;

    if (ethHeader.ethertype === 0x0800) {
      // IPv4
      sourceIP = ip.toString(packetData.subarray(26, 30));
      destinationIP = ip.toString(packetData.subarray(30, 34));

      const protocol = packetData.readUInt8(23);
      if (protocol === 6) {
        // TCP
        transportHeader = tcpHeader(packetData.subarray(34));
      } else if (protocol === 17) {
        // UDP
        transportHeader = udpHeader(packetData.subarray(34));
      }

      const dnsPayload = packetData.subarray(42);
      parsedDnsQuery = parseDnsQuery(dnsPayload);
    }

    const packet = {
      timestamp: new Date(tsSec * 1000 + tsUsec / 1000),
      length: inclLen,
      originalLength: origLen,
      ethernet: ethHeader,
      protocol: ethHeader.ethertype === 0x0800 ? "IPv4" : "Unknown",
      transport: transportHeader,
      sourceIP: sourceIP,
      destinationIP: destinationIP,
      parsedDnsQuery: parsedDnsQuery,
    };

    packets.push(packet);

    offset += 16 + inclLen;
  }

  return packets;
}

exports.parsePcapFile = parsePcapFile;
