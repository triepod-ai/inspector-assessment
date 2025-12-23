import { createConcurrencyLimit } from "./concurrencyLimit";

describe("createConcurrencyLimit", () => {
  it("should limit concurrent operations to the specified concurrency", async () => {
    const concurrency = 2;
    const limit = createConcurrencyLimit(concurrency);

    let activeCount = 0;
    let maxActiveCount = 0;

    const createTask = (id: number, delay: number) =>
      limit(async () => {
        activeCount++;
        maxActiveCount = Math.max(maxActiveCount, activeCount);
        await new Promise((resolve) => setTimeout(resolve, delay));
        activeCount--;
        return id;
      });

    const results = await Promise.all([
      createTask(1, 50),
      createTask(2, 50),
      createTask(3, 50),
      createTask(4, 50),
    ]);

    expect(results).toEqual([1, 2, 3, 4]);
    expect(maxActiveCount).toBeLessThanOrEqual(concurrency);
  });

  it("should process all tasks even when some fail", async () => {
    const limit = createConcurrencyLimit(2);

    const results = await Promise.allSettled([
      limit(async () => "success1"),
      limit(async () => {
        throw new Error("fail");
      }),
      limit(async () => "success2"),
    ]);

    expect(results[0]).toEqual({ status: "fulfilled", value: "success1" });
    expect(results[1]).toEqual({
      status: "rejected",
      reason: new Error("fail"),
    });
    expect(results[2]).toEqual({ status: "fulfilled", value: "success2" });
  });

  it("should throw error for invalid concurrency", () => {
    expect(() => createConcurrencyLimit(0)).toThrow(
      "Concurrency must be at least 1",
    );
    expect(() => createConcurrencyLimit(-1)).toThrow(
      "Concurrency must be at least 1",
    );
  });

  it("should work with concurrency of 1 (sequential)", async () => {
    const limit = createConcurrencyLimit(1);
    const order: number[] = [];

    await Promise.all([
      limit(async () => {
        order.push(1);
        await new Promise((resolve) => setTimeout(resolve, 10));
      }),
      limit(async () => {
        order.push(2);
        await new Promise((resolve) => setTimeout(resolve, 10));
      }),
      limit(async () => {
        order.push(3);
      }),
    ]);

    expect(order).toEqual([1, 2, 3]);
  });
});
