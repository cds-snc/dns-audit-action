const core = require("@actions/core");
const { spawn, exec } = require('child_process');

const fs = require("fs");
const pcap_parser = require("./pcap_parser");

const main = () => {
    // Check if dns.pcap exists
    if (!fs.existsSync("dns.pcap")) {

        const command = 'sudo';
        const args = ['tcpdump', '-n', '-l', '-w', 'dns.pcap', 'port', '443'];

        console.log("Starting tcpdump...");
        // Start the child process
        const tcpdumpProcess = spawn(command, args, {
            detached: true, // Detach the child process from the parent
            stdio: 'ignore', // Ignore stdin, stdout, and stderr
        });
        console.log("tcpdump started.");

        // Unref the child process to allow the parent process to exit
        tcpdumpProcess.unref();

    } else {

        console.log("Killing tcpdump...");
        exec('sudo pkill tcpdump', (err, stdout, stderr) => {
            if (err) {
                console.log(err);
                return;
            }
            console.log(stdout);
            console.log(stderr);
        });

        // Convert PCAP to JSON
        const packets = pcap_parser.parsePcapFile("dns.pcap");
        console.log(JSON.stringify(packets, null, 2));
    }
};

main();

exports.main = main;
