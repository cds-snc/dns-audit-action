const core = require("@actions/core");
const { spawn, exec } = require('child_process');

const fs = require("fs");
const pcap_parser = require("./pcap_parser");

const sleepSync = (ms) => {
    const end = new Date().getTime() + ms;
    while (new Date().getTime() < end) { /* do nothing */ }
}

const main = () => {

    // Get the inputs
    const echoResults = core.getInput("echo-results");
    const startTcpdump = core.getInput("start-tcpdump");

    // Check if dns.pcap exists
    if (startTcpdump && !fs.existsSync("dns.pcap")) {

        const command = 'sudo';
        const args = ['tcpdump', '-n', '-i', 'any', '-w', 'tmp/dns.pcap', 'port', '53'];

        const tcpdumpProcess = spawn(command, args, {
            detached: true, // Detach the child process from the parent
            stdio: 'ignore', // Ignore stdin, stdout, and stderr
        });

        // Let tcpdump run for 2 seconds to get started
        sleepSync(2000);

        // Unref the child process to allow the parent process to exit
        tcpdumpProcess.unref();

    } else if (echoResults && fs.existsSync("tmp/dns.pcap")) {
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
        const packets = pcap_parser.parsePcapFile("tmp/dns.pcap");
        console.log(packets);
    } else {
        console.log("No DNS packets capture started.");
    }
}

main();

exports.main = main;
