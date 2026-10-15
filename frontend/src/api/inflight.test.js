/**
 * Sharing one request between callers who asked the same thing.
 */
import { once, requestKey, resetInFlight } from "./inflight";

beforeEach(() => resetInFlight());

describe("the key a request is known by", () => {
  it("does not care what order the params were built in", () => {
    expect(requestKey("/get-alerts", { page: 1, severity: 4 })).toBe(
      requestKey("/get-alerts", { severity: 4, page: 1 })
    );
  });

  it("leaves out what would not be sent", () => {
    expect(requestKey("/get-alerts", { page: 1, agent_name: undefined, category: "" })).toBe(
      "/get-alerts?page=1"
    );
  });

  it("tells two different questions apart", () => {
    expect(requestKey("/get-alerts", { page: 1 })).not.toBe(
      requestKey("/get-alerts", { page: 2 })
    );
  });
});

describe("one call for one question", () => {
  it("hands the same promise to everyone who asks while it is running", async () => {
    const run = jest.fn(() => Promise.resolve("answer"));

    const a = once("k", run);
    const b = once("k", run);

    expect(a).toBe(b);
    expect(run).toHaveBeenCalledTimes(1);
    await expect(a).resolves.toBe("answer");
  });

  it("keeps different questions apart", async () => {
    const run = jest.fn(() => Promise.resolve(1));
    await Promise.all([once("a", run), once("b", run)]);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("asks again once the answer has landed, because the answer can change", async () => {
    const run = jest.fn(() => Promise.resolve(1));

    await once("k", run);
    await once("k", run);

    // the alerts list refreshes on a timer; caching would serve it the reading
    // it already had
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("does not remember a failure as the answer", async () => {
    const run = jest
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce("second time");

    await expect(once("k", run)).rejects.toThrow("network");
    await expect(once("k", run)).resolves.toBe("second time");
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("shares a rejection with everyone who was waiting on it", async () => {
    const run = jest.fn(() => Promise.reject(new Error("boom")));

    const a = once("k", run);
    const b = once("k", run);

    await expect(a).rejects.toThrow("boom");
    await expect(b).rejects.toThrow("boom");
    expect(run).toHaveBeenCalledTimes(1);
  });
});
