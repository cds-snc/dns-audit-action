const core = require("@actions/core");
const exec = require("@actions/exec");

const main = () => {
  // Start TCPDump in background
  exec.exec(`sudo tcpdump -n -l -w tmp/dns.pcap port 53 &`);
};

main();

exports.main = main;
