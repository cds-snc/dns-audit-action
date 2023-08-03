const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs");
const pcap_parser = require("./pcap_parser");

const main = () => {
    // Check if dns.pcap exists
    if (!fs.existsSync("tmp/dns.pcap")) {
        // Start TCPDump
        exec.exec('sudo', ['tcpdump', '-n', '-w tmp/dns.pcap', 'port 53']);
    } else {
        // Kill all TCPDump processes
        exec.exec('sudo', ['killall', 'tcpdump']);

        // Convert PCAP to JSON
        const packets = pcap_parser.parsePcapFile("tmp/dns.pcap");
        console.log(JSON.stringify(packets, null, 2));
    }
};

main();

exports.main = main;
