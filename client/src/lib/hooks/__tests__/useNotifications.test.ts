import { renderHook, act } from "@testing-library/react";
import { useNotifications } from "../useNotifications";
import { ServerNotification } from "@modelcontextprotocol/sdk/types.js";

describe("useNotifications", () => {
  const createMockNotification = (
    overrides?: Partial<ServerNotification>,
  ): ServerNotification => ({
    method: "notifications/message",
    params: {
      level: "info",
      logger: "test",
      data: "Test notification",
    },
    ...overrides,
  });

  describe("initial state", () => {
    it("should return empty notifications array initially", () => {
      const { result } = renderHook(() => useNotifications());

      expect(result.current.notifications).toEqual([]);
      expect(result.current.unreadCount).toBe(0);
    });
  });

  describe("addNotification", () => {
    it("should add a notification to the list", () => {
      const { result } = renderHook(() => useNotifications());
      const notification = createMockNotification();

      act(() => {
        result.current.addNotification(notification);
      });

      expect(result.current.notifications).toHaveLength(1);
      expect(result.current.notifications[0]).toEqual(notification);
      expect(result.current.unreadCount).toBe(1);
    });

    it("should add multiple notifications in order", () => {
      const { result } = renderHook(() => useNotifications());
      const notification1 = createMockNotification({
        params: { level: "info", logger: "test", data: "First" },
      });
      const notification2 = createMockNotification({
        params: { level: "warning", logger: "test", data: "Second" },
      });

      act(() => {
        result.current.addNotification(notification1);
      });

      act(() => {
        result.current.addNotification(notification2);
      });

      expect(result.current.notifications).toHaveLength(2);
      expect(result.current.notifications[0]).toEqual(notification1);
      expect(result.current.notifications[1]).toEqual(notification2);
      expect(result.current.unreadCount).toBe(2);
    });
  });

  describe("clearNotifications", () => {
    it("should clear all notifications", () => {
      const { result } = renderHook(() => useNotifications());
      const notification = createMockNotification();

      act(() => {
        result.current.addNotification(notification);
        result.current.addNotification(notification);
        result.current.addNotification(notification);
      });

      expect(result.current.notifications).toHaveLength(3);

      act(() => {
        result.current.clearNotifications();
      });

      expect(result.current.notifications).toHaveLength(0);
      expect(result.current.unreadCount).toBe(0);
    });

    it("should work when notifications are already empty", () => {
      const { result } = renderHook(() => useNotifications());

      act(() => {
        result.current.clearNotifications();
      });

      expect(result.current.notifications).toHaveLength(0);
    });
  });

  describe("unreadCount", () => {
    it("should track notification count correctly", () => {
      const { result } = renderHook(() => useNotifications());

      expect(result.current.unreadCount).toBe(0);

      act(() => {
        result.current.addNotification(createMockNotification());
      });
      expect(result.current.unreadCount).toBe(1);

      act(() => {
        result.current.addNotification(createMockNotification());
      });
      expect(result.current.unreadCount).toBe(2);

      act(() => {
        result.current.clearNotifications();
      });
      expect(result.current.unreadCount).toBe(0);
    });
  });
});
