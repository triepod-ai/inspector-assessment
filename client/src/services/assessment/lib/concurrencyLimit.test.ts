import {
  createConcurrencyLimit,
  QUEUE_WARNING_THRESHOLD,
} from "./concurrencyLimit";
import { Logger } from "./logger";

// Mock logger for testing
const createMockLogger = (): Logger & { warn: jest.Mock } => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  child: jest.fn().mockReturnThis(),
  isLevelEnabled: jest.fn().mockReturnValue(true),
});

describe("createConcurrencyLimit", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

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

  it("should warn exactly once when queue exceeds threshold", async () => {
    const mockLogger = createMockLogger();
    const limit = createConcurrencyLimit(1, mockLogger);

    // Enqueue more than QUEUE_WARNING_THRESHOLD tasks
    // Using concurrency=1 means all but one task will queue up
    const taskCount = QUEUE_WARNING_THRESHOLD + 500;
    const tasks = Array.from({ length: taskCount }, (_, i) =>
      limit(async () => i),
    );

    // Wait for all tasks to complete
    await Promise.all(tasks);

    // Should have warned exactly ONCE (not 500 times) - deduplication check
    expect(mockLogger.warn).toHaveBeenCalledTimes(1);
    expect(mockLogger.warn).toHaveBeenCalledWith(
      "Queue depth exceeded threshold",
      expect.objectContaining({
        queueDepth: expect.any(Number),
        threshold: QUEUE_WARNING_THRESHOLD,
        activeCount: expect.any(Number),
        concurrency: 1,
      }),
    );
  });

  it("should not warn when queue is below threshold", async () => {
    const mockLogger = createMockLogger();
    const limit = createConcurrencyLimit(1, mockLogger);

    // Enqueue fewer tasks than threshold
    const taskCount = 100;
    const tasks = Array.from({ length: taskCount }, (_, i) =>
      limit(async () => i),
    );

    await Promise.all(tasks);

    // Should NOT have warned
    expect(mockLogger.warn).not.toHaveBeenCalled();
  });
});
