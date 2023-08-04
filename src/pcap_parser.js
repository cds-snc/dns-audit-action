const fs = require('fs');

const pcapHeader = (buffer) => {
  return {
    magicNumLEr: buffer.readUInt32LE(0),
    versionMajor: buffer.readUInt16LE(4),
    versionMinor: buffer.readUInt16LE(6),
    thiszone: buffer.readInt32LE(8),
    sigfigs: buffer.readUInt32LE(12),
    snaplen: buffer.readUInt32LE(16),
    network: buffer.readUInt32LE(20),
  }
}

const sll2Header = (buffer) => {
  return {
    protocol: buffer.readUInt16LE(0),
    interface: buffer.readUInt32LE(4),
    arphrdType: buffer.readUInt16LE(8),
    packetType: buffer.readUInt8(10),
    addressLength: buffer.readUInt8(11),
    address: buffer.subarray(12, 12 + buffer.readUInt8(11)).toString('hex').match(/.{2}/g).join(':'),
  }
}

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
    options: buffer.subarray(20, 20 + ((buffer.readUInt8(0) & 0x0f) * 4)),
  }
}

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

  try {

    const identification = payload.readUInt16BE(0); // Identification is the first 2 bytes
    const flags = payload.readUInt16BE(2); // Flags field is at offset 2
    const isResponse = (flags & 0x8000) !== 0; // Most significant bit indicates response
    const opcode = (flags >> 11) & 0x0f; // Opcode is the 4 bits following the response bit
    const authoritativeAnswer = (flags & 0x0400) !== 0;
    const truncated = (flags & 0x0200) !== 0;
    const recursionDesired = (flags & 0x0100) !== 0;
    const recursionAvailable = (flags & 0x0080) !== 0;
    const responseCode = flags & 0x000f; // 4 bits for the response code
    const numberOfQueries = payload.readUInt16BE(4); // Number of queries is 2 bytes after the flags
    const numberOfAnswers = payload.readUInt16BE(6); // Number of answers is 2 bytes after the number of queries
    const numberOfAuthorityRecords = payload.readUInt16BE(8); // Number of authority records is 2 bytes after the number of answers
    const numberOfAdditionalRecords = payload.readUInt16BE(10); // Number of additional records is 2 bytes after the number of authority records

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
    const queryClass = payload.readUInt16BE(offset + 3); // Query class is 2 bytes after the query types

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

function parsePcapHeader(filename) {
  const pcapData = fs.readFileSync(filename);
  const pcapHeaderData = pcapHeader(pcapData);
  let packets = [];

  let offset = 24; // Skip the PCAP global header

  while (offset < pcapData.length) {
    const tsSec = pcapData.readUInt32LE(offset);
    const tsUsec = pcapData.readUInt32LE(offset + 4);
    const inclLen = pcapData.readUInt32LE(offset + 8);
    const origLen = pcapData.readUInt32LE(offset + 12);
    const packetData = pcapData.subarray(offset + 16, offset + 16 + inclLen);

    if (pcapHeaderData.network === 276) {

      const sllHeader = sll2Header(packetData);
      const ipv4HeaderData = ipv4Header(packetData.subarray(20));
      if (ipv4HeaderData.protocol === 17) {
        const udpHeaderData = udpHeader(packetData.subarray(40));
        const dnsData = packetData.subarray(48);
        const dnsQuery = parseDnsQuery(dnsData);
        packets.push({
          timestamp: new Date(tsSec * 1000 + tsUsec / 1000),
          ...dnsQuery
        }
        )
      }
    }

    offset += 16 + inclLen;
  }

  return packets;
}

exports.parsePcapHeader = parsePcapHeader;