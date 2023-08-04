const pcapParser = require("./pcap_parser");
const { sleepSync } = require('./sleep');
const { exec } = require('child_process');

const filePcap = '/tmp/dns.pcap';

const supressOutput = process.env.SUPRESS_DNS_AUDIT_OUTPUT || false;

const post = () => {

    exec('sudo pkill tcpdump', (err, stdout, stderr) => {
        if (err) {
            console.log(err);
            return;
        }
        console.log(stdout);
        console.log(stderr);
    });

    // Let tcpdump finish
    sleepSync(5000);

    // Convert PCAP to JSON
    if (!supressOutput) {
        const packets = pcapParser.parsePcapFile(filePcap);
        console.log(packets);
    }

}

post();

exports.post = post;