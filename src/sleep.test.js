const { sleepSync } = require("./sleep");

describe("sleepSync function", () => {
  it("should sleep for the specified time", () => {
    const startTime = new Date().getTime();

    sleepSync(100); // Sleep for 100 milliseconds

    const endTime = new Date().getTime();
    const elapsedTime = endTime - startTime;

    expect(elapsedTime).toBeGreaterThanOrEqual(100);
  });
});
