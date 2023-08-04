const core = require("@actions/core");
const { spawn, exec } = require('child_process');

const fs = require("fs");
const pcap_parser = require("./pcap_parser");
const sleepSync = require('./sleep');

const filePcap = '/tmp/dns.pcap';



const terminateTcpdump = (filename) => {
    exec('sudo pkill tcpdump', (err, stdout, stderr) => {
        if (err) {
            console.log(err);
            return;
        }
        console.log(stdout);
        console.log(stderr);
    });

    // Let tcpdump finish
    sleepSync.sleepSync(5000);

    // Convert PCAP to JSON
    const packets = pcap_parser.parsePcapFile(filePcap);
    console.log("writing to file ...")
}

const main = () => {

    // Get the inputs
    const startTcpdump = core.getInput("start-tcpdump");
    const outputFile = core.getInput("output-file");

    // Check if dns.pcap exists
    if (startTcpdump && !fs.existsSync(filePcap)) {

        // Start tcpdump
        console.log("Starting tcpdump");

        const command = 'sudo';
        const args = ['tcpdump', '-n', '-i', 'any', '-w', filePcap, 'port', '53'];

        const tcpdumpProcess = spawn(command, args, {
            detached: true, // Detach the child process from the parent
            stdio: 'ignore', // Ignore stdin, stdout, and stderr
        });

        // Let tcpdump run for 2 seconds to get started
        sleepSync.sleepSync(2000);

        // Unref the child process to allow the parent process to exit
        tcpdumpProcess.unref();

    } else if (fs.existsSync(filePcap && outputFile)) {
        terminateTcpdump(outputFile);
    } else {
        console.log("No DNS packets capture started.");
    }
}

main();

exports.main = main;
