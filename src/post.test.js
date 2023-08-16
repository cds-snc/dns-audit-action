const core = require("@actions/core");
const { post } = require("./post");
const pcapParser = require("./pcap_parser");
const { exec } = require("child_process");
const fs = require("fs");
const sleepModule = require("./sleep");

jest.mock("@actions/core", () => ({
  getInput: jest.fn(),
  debug: jest.fn(),
}));

jest.mock("child_process", () => ({
  exec: jest.fn(),
}));

jest.mock("fs", () => ({
  existsSync: jest.fn(),
}));

jest.mock("./pcap_parser", () => ({
  parsePcapFile: jest.fn(),
}));

jest.mock("./sleep", () => ({
  sleepSync: jest.fn(),
}));

describe("post function", () => {
  beforeEach(() => {
    jest.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should not log packets when suppressOutput is true", () => {
    core.getInput.mockReturnValue("/tmp/test.pcap");
    fs.existsSync.mockReturnValue(true);
    process.env.SUPRESS_DNS_AUDIT_OUTPUT = "true";

    post();
    console.log(console.log.mock.calls);
    expect(console.log).toHaveBeenCalledWith(undefined);
  });

  it("should call the necessary functions and log packets", () => {
    core.getInput.mockReturnValue("/tmp/test.pcap");
    fs.existsSync.mockReturnValue(true);
    pcapParser.parsePcapFile.mockReturnValueOnce("mockedParsedData");

    post();

    expect(exec).toHaveBeenCalledWith(
      "sudo pkill tcpdump",
      expect.any(Function)
    );
    expect(sleepModule.sleepSync).toHaveBeenCalledWith(5000);
    expect(core.getInput).toHaveBeenCalledWith("file-path");
    expect(pcapParser.parsePcapFile).toHaveBeenCalledWith("/tmp/test.pcap");
    expect(console.log).toHaveBeenCalledWith("mockedParsedData");
    expect(exec).toHaveBeenCalledWith(
      "sudo rm -rf /tmp/test.pcap",
      expect.any(Function)
    );
  });

  it("should do nothing when the file does not exist", () => {
    core.getInput.mockReturnValue("/tmp/test.pcap");
    fs.existsSync.mockReturnValue(false);

    post();

    expect(exec).not.toHaveBeenCalled();
    expect(sleepModule.sleepSync).not.toHaveBeenCalled();
    expect(pcapParser.parsePcapFile).not.toHaveBeenCalled();
  });
});
