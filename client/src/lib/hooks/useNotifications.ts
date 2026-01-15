import { useState, useCallback } from "react";
import { ServerNotification } from "@modelcontextprotocol/sdk/types.js";

/**
 * Return type for the useNotifications hook
 */
export interface UseNotificationsReturn {
  /** Array of server notifications */
  notifications: ServerNotification[];
  /** Add a new notification to the list */
  addNotification: (notification: ServerNotification) => void;
  /** Clear all notifications */
  clearNotifications: () => void;
  /** Number of unread notifications */
  unreadCount: number;
}

/**
 * Custom hook for managing server notification state
 *
 * Extracts notification management logic from App component for better
 * testability and maintainability.
 *
 * @returns Notification state, add function, clear function, and unread count
 */
export function useNotifications(): UseNotificationsReturn {
  const [notifications, setNotifications] = useState<ServerNotification[]>([]);

  const addNotification = useCallback((notification: ServerNotification) => {
    setNotifications((prev) => [...prev, notification]);
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  return {
    notifications,
    addNotification,
    clearNotifications,
    unreadCount: notifications.length,
  };
}

export default useNotifications;
