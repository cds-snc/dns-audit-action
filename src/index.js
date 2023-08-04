const core = require("@actions/core");
const { spawn, exec } = require('child_process');

const fs = require("fs");
const pcap_parser = require("./pcap_parser");

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const main = () => {
    // Check if dns.pcap exists
    if (!fs.existsSync("dns.pcap")) {

        const command = 'sudo';
        const args = ['tcpdump', '-n', '-i', 'any', '-w', 'dns.pcap', 'port', '53'];

        const tcpdumpProcess = spawn(command, args, {
            detached: true, // Detach the child process from the parent
            stdio: 'ignore', // Ignore stdin, stdout, and stderr
        });

        sleep(2000);

        // Unref the child process to allow the parent process to exit
        tcpdumpProcess.unref();

    } else {
        exec('sudo pkill tcpdump', (err, stdout, stderr) => {
            if (err) {
                console.log(err);
                return;
            }
            console.log(stdout);
            console.log(stderr);
        });

        // Let tcpdump finish
        sleep(5000);

        // Convert PCAP to JSON
        const packets = pcap_parser.parsePcapFile("dns.pcap");
        console.log(packets);
    };
}

main();

exports.main = main;
