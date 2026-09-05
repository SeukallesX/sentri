export type SecurityEventType =
  | "message"
  | "url"
  | "login"
  | "device_change"
  | "password_reset"
  | "transaction"
  | "account_change";

export type SecurityEventSource =
  | "user"
  | "system"
  | "simulation"
  | "api";

export interface SecurityEventMetadata {
  timestamp: string;

  source: SecurityEventSource;

  ipAddress?: string;
  deviceId?: string;
  userAgent?: string;
  location?: string;
  accountId?: string;
  sessionId?: string;
  transactionId?: string;

  amount?: number;
  currency?: string;
}

export interface SecurityEvent {
  id: string;

  type: SecurityEventType;

  content: string;

  metadata: SecurityEventMetadata;
}