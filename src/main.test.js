const core = require("@actions/core");
const fs = require("fs");
const { spawn } = require("child_process");
const { main } = require("./main");
const sleepModule = require("./sleep");

// Mocking core module
jest.mock("@actions/core", () => ({
  getInput: jest.fn(),
  debug: jest.fn(),
  warning: jest.fn(),
}));

// Mocking fs module
jest.mock("fs", () => ({
  existsSync: jest.fn(),
  writeFileSync: jest.fn(),
}));

// Mocking child_process module
jest.mock("child_process", () => ({
  spawn: jest.fn(),
  exec: jest.fn(),
}));

// Mocking pcap_parser module
jest.mock("./pcap_parser", () => ({
  parsePcapFile: jest.fn(() => []),
}));

// Mocking sleep module
jest.mock("./sleep", () => ({
  sleepSync: jest.fn(),
}));

describe("main function", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should start tcpdump and terminate correctly", () => {
    core.getInput
      .mockReturnValueOnce("true") // Simulate starting tcpdump
      .mockReturnValueOnce("/tmp/dns.pcap")
      .mockReturnValueOnce("/tmp/output.json");

    fs.existsSync.mockReturnValue(false); // Simulate pcap file does not exist

    const spawnMock = new (jest.fn().mockImplementation(() => ({
      unref: jest.fn(),
    })))();
    spawn.mockReturnValue(spawnMock);

    main();

    // Assert spawn function called with correct arguments
    expect(spawn).toHaveBeenCalledWith(
      "sudo",
      ["tcpdump", "-n", "-i", "any", "-w", "/tmp/dns.pcap", "port", "53"],
      {
        detached: true,
        stdio: "ignore",
      }
    );

    // Assert sleepSync called to wait
    expect(sleepModule.sleepSync).toHaveBeenCalledWith(2000);

    // Simulate unref call
    expect(spawnMock.unref).toHaveBeenCalled();
  });

  it("should terminate tcpdump and write data to file correctly", () => {
    core.getInput
      .mockReturnValueOnce("false") // Simulate not starting tcpdump
      .mockReturnValueOnce("/tmp/dns.pcap")
      .mockReturnValueOnce("/tmp/output.json");

    fs.existsSync.mockReturnValue(true); // Simulate pcap file existence

    main();

    // Assert terminateTcpdump function called correctly
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      "/tmp/output.json",
      expect.any(String)
    );
  });

  it("should handle case when pcap file does not exist", () => {
    core.getInput
      .mockReturnValueOnce(null) // Simulate not starting tcpdump
      .mockReturnValueOnce("/tmp/nonexistent.pcap")
      .mockReturnValueOnce("/tmp/output.json");

    fs.existsSync.mockReturnValue(false); // Simulate pcap file non-existence

    main();

    // Assert warning called when pcap file does not exist
    expect(core.warning).toHaveBeenCalledWith(
      "No DNS packets capture started. Doing nothing."
    );
  });

  // Additional test cases for specific scenarios can be added here
});
