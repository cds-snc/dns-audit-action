const fs = require("fs");

const pcapHeader = (buffer) => {
  return {
    magicNumLEr: buffer.readUInt32LE(0),
    versionMajor: buffer.readUInt16LE(4),
    versionMinor: buffer.readUInt16LE(6),
    thiszone: buffer.readInt32LE(8),
    sigfigs: buffer.readUInt32LE(12),
    snaplen: buffer.readUInt32LE(16),
    network: buffer.readUInt32LE(20),
  };
};

const ipv4Header = (buffer) => {
  return {
    version: buffer.readUInt8(0) >> 4,
    headerLength: buffer.readUInt8(0) & 0x0f,
    typeOfService: buffer.readUInt8(1),
    totalLength: buffer.readUInt16LE(2),
    identification: buffer.readUInt16LE(4),
    flags: buffer.readUInt8(6) >> 5,
    fragmentOffset: buffer.readUInt16LE(6) & 0x1fff,
    timeToLive: buffer.readUInt8(8),
    protocol: buffer.readUInt8(9),
    headerChecksum: buffer.readUInt16LE(10),
    sourceAddress: buffer.subarray(12, 16),
    destinationAddress: buffer.subarray(16, 20),
    options: buffer.subarray(20, 20 + (buffer.readUInt8(0) & 0x0f) * 4),
  };
};

function parseDnsQuery(payload) {
  try {
    let queryName = "";
    let offset = 12; // Start of the query name

    while (payload[offset] !== 0) {
      const labelLength = payload[offset];
      queryName +=
        payload.slice(offset + 1, offset + 1 + labelLength).toString("utf8") +
        ".";
      offset += labelLength + 1;
      // In case we have a broken packet
      if (queryName.endsWith("..")) {
        break;
      }
    }

    const queryType = payload.readUInt16BE(offset + 1); // Query type is 2 bytes after the query name

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
      queryName,
      queryType: queryTypeName,
    };
  } catch (error) {
    return null;
  }
}

function parsePcapFile(filename) {
  const pcapData = fs.readFileSync(filename);
  const pcapHeaderData = pcapHeader(pcapData);
  let packets = [];

  let offset = 24; // Skip the PCAP global header

  while (offset < pcapData.length) {
    const tsSec = pcapData.readUInt32LE(offset);
    const tsUsec = pcapData.readUInt32LE(offset + 4);
    const inclLen = pcapData.readUInt32LE(offset + 8);
    const packetData = pcapData.subarray(offset + 16, offset + 16 + inclLen);

    if (pcapHeaderData.network === 276) {
      const ipv4HeaderData = ipv4Header(packetData.subarray(20));
      if (ipv4HeaderData.protocol === 17) {
        const dnsData = packetData.subarray(48);
        const dnsQuery = parseDnsQuery(dnsData);
        packets.push({
          timestamp: new Date(tsSec * 1000 + tsUsec / 1000),
          ...dnsQuery,
        });
      }
    }

    offset += 16 + inclLen;
  }

  return packets;
}

exports.parsePcapFile = parsePcapFile;
