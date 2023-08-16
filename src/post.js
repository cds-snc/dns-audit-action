const core = require("@actions/core");
const pcapParser = require("./pcap_parser");
const { exec } = require("child_process");
const fs = require("fs");

const { sleepSync } = require("./sleep");

const supressOutput = process.env.SUPRESS_DNS_AUDIT_OUTPUT || false;

const post = () => {
  const filePcap = core.getInput("file-path");

  // Only clean up if the file exists
  if (fs.existsSync(filePcap)) {
    exec("sudo pkill tcpdump", (err) => {
      if (err) {
        return;
      }
    });

    // Let tcpdump finish
    sleepSync(5000);

    // Convert PCAP to JSON
    if (!supressOutput) {
      const packets = pcapParser.parsePcapFile(filePcap);
      console.log(packets);
    }

    // Delete file to avoid multiple runs
    exec(`sudo rm -rf ${filePcap}`, (err) => {
      if (err) {
        return;
      }
    });
  }
};

post();

exports.post = post;
