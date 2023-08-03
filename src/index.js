const core = require("@actions/core");
const exec = require("@actions/exec");
const pcap_parser = require("./pcap_parser");

const cleanup = () => {

    // Kill all TCPDump processes
    exec.exec(`sudo killall tcpdump`);

    // Convert PCAP to JSON
    const packets = pcap_parser.parsePcapFile("tmp/dns.pcap");
    console.log(JSON.stringify(packets, null, 2));

};

cleanup();

exports.cleanup = cleanup;
