const core = require("@actions/core");
const exec = require("@actions/exec");
const pcap_parser = require("./pcap_parser");

const arg = process.argv[2];

const main = () => {


    if (arg == "start") {
        // Start TCPDump
        exec.exec(`sudo tcpdump -n -l -w tmp/dns.pcap port 53 &`);

    } else if (arg == "cleanup") {

        // Kill all TCPDump processes
        exec.exec(`sudo killall tcpdump`);

        // Convert PCAP to JSON
        const packets = pcap_parser.parsePcapFile("tmp/dns.pcap");
        console.log(JSON.stringify(packets, null, 2));

    } else {
        console.log("Invalid argument");
    }
};

main();

exports.main = main;
