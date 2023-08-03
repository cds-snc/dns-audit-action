const core = require("@actions/core");
import { $ } from 'execa';
const fs = require("fs");
const pcap_parser = require("./pcap_parser");

const main = () => {
    // Check if dns.pcap exists
    if (!fs.existsSync("dns.pcap")) {
        // Start TCPDump
        let options = {
            detached: true,
            stdio: "ignore",
        };

        let child = $(`sudo tcpdump -n -w dns.pcap port 53`, options);
        child.unref();

    } else {
        // Kill all TCPDump processes
        $`sudo killall tcpdump`;

        // Convert PCAP to JSON
        const packets = pcap_parser.parsePcapFile("dns.pcap");
        console.log(JSON.stringify(packets, null, 2));
    }
};

main();

exports.main = main;
