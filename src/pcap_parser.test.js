const fs = require("fs");
const { parsePcapFile } = require("./pcap_parser");

describe("parsePcapFile function", () => {
  it("should parse PCAP data correctly", () => {
    const result = parsePcapFile("./src/fixtures/dns_pcap");

    expect(result.length).toBe(51);
    expect(result[0]).toStrictEqual({
      timestamp: new Date("2023-08-03T23:41:13.195Z"),
      queryName: "objects.githubusercontent.com.",
      queryType: "A",
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });
});
