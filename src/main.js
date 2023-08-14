const core = require("@actions/core");
const fs = require("fs");
const { spawn, exec } = require('child_process');

const pcap_parser = require("./pcap_parser");
const { sleepSync } = require('./sleep');

const filePcap = '/tmp/dns.pcap';

const terminateTcpdump = (filename) => {
    exec('sudo pkill tcpdump', (err, stdout, stderr) => {
        if (err) {
            core.debug(err);
            return;
        }
        core.debug(stdout);
        core.debug(stderr);
    });

    // Let tcpdump finish
    sleepSync(5000);

    // Convert PCAP to JSON
    const packets = pcap_parser.parsePcapFile(filePcap);

    const ciData = {
        actor: process.env.GITHUB_ACTOR,
        dnsQueries: packets,
        dnsQueryCount: packets.length,
        eventName: process.env.GITHUB_EVENT_NAME,
        job: process.env.GITHUB_JOB,
        repository: process.env.GITHUB_REPOSITORY,
        runNumber: process.env.GITHUB_RUN_NUMBER,
        sha: process.env.GITHUB_SHA,
        workflow: process.env.GITHUB_WORKFLOW,
        workflow_ref: process.env.GITHUB_WORKFLOW_REF,
    }

    // Write to file
    fs.writeFileSync(filename, JSON.stringify(ciData));
}

const main = () => {

    // Get the inputs
    const startTcpdump = core.getInput("start-tcpdump");
    const outputFile = core.getInput("output-file");

    // Check if dns.pcap exists
    if (startTcpdump && !fs.existsSync(filePcap)) {

        // Start tcpdump
        core.debug("Starting tcpdump");

        const command = 'sudo';
        const args = ['tcpdump', '-n', '-i', 'any', '-w', filePcap, 'port', '53'];

        const tcpdumpProcess = spawn(command, args, {
            detached: true, // Detach the child process from the parent
            stdio: 'ignore', // Ignore stdin, stdout, and stderr
        });

        // Let tcpdump run for 2 seconds to get started
        sleepSync(2000);

        // Unref the child process to allow the parent process to exit
        tcpdumpProcess.unref();

    } else if (fs.existsSync(filePcap) && outputFile) {
        terminateTcpdump(outputFile);
    } else {
        core.warning("No DNS packets capture started. Doing nothing.");
    }
}

main();

exports.main = main;
