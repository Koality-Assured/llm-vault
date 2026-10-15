import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ClipboardState } from "../types.js";
import { clearClipboardNow, copySecretToClipboard, subscribeClipboard } from "./clipboard.js";

describe("clipboard", () => {
  let clipboardText = "";
  let shouldFailWrite = false;
  let listeners: Record<string, ((event?: unknown) => void)[]> = {};

  beforeEach(() => {
    vi.useFakeTimers();
    clipboardText = "";
    shouldFailWrite = false;
    listeners = {};

    // Mock window and document event listeners
    const mockWindow = {
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners[type]) listeners[type] = [];
        listeners[type]?.push(listener);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (listeners[type]) {
          listeners[type] = listeners[type]?.filter((l) => l !== listener);
        }
      },
    };

    const mockDocument = {
      visibilityState: "visible",
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners[type]) listeners[type] = [];
        listeners[type]?.push(listener);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (listeners[type]) {
          listeners[type] = listeners[type]?.filter((l) => l !== listener);
        }
      },
    };

    const mockNavigator = {
      clipboard: {
        writeText: vi.fn(async (text: string) => {
          if (shouldFailWrite) {
            throw new Error("NotAllowedError: Document is not focused.");
          }
          clipboardText = text;
        }),
      },
    };

    Object.defineProperty(globalThis, "window", {
      value: mockWindow,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis, "document", {
      value: mockDocument,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis, "navigator", {
      value: mockNavigator,
      writable: true,
      configurable: true,
    });
  });

  afterEach(async () => {
    await clearClipboardNow();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("copies secret to clipboard and initializes countdown", async () => {
    const states: ClipboardState[] = [];
    const unsubscribe = subscribeClipboard((st) => states.push({ ...st }));

    const success = await copySecretToClipboard("super-secret-token", "sec_01clipboard001", 10);
    expect(success).toBe(true);
    expect(clipboardText).toBe("super-secret-token");

    const latest = states[states.length - 1];
    expect(latest?.activeSecretId).toBe("sec_01clipboard001");
    expect(latest?.secondsRemaining).toBe(10);
    expect(latest?.totalDurationSeconds).toBe(10);

    unsubscribe();
  });

  it("decrements countdown and auto-clears clipboard when timer expires", async () => {
    const states: ClipboardState[] = [];
    const unsubscribe = subscribeClipboard((st) => states.push({ ...st }));

    await copySecretToClipboard("ephemeral-value", "sec_01clipboard002", 3);
    expect(clipboardText).toBe("ephemeral-value");

    // Advance 1s
    vi.advanceTimersByTime(1000);
    expect(states[states.length - 1]?.secondsRemaining).toBe(2);

    // Advance 1s
    vi.advanceTimersByTime(1000);
    expect(states[states.length - 1]?.secondsRemaining).toBe(1);

    // Advance 1s to expiration
    await vi.advanceTimersByTimeAsync(1000);

    expect(clipboardText).toBe("");
    const finalState = states[states.length - 1];
    expect(finalState?.activeSecretId).toBeNull();
    expect(finalState?.secondsRemaining).toBe(0);
    expect(finalState?.pendingFocusPurge).toBe(false);

    unsubscribe();
  });

  it("queues pending focus purge if writeText fails due to tab blur, clearing on return", async () => {
    const states: ClipboardState[] = [];
    const unsubscribe = subscribeClipboard((st) => states.push({ ...st }));

    await copySecretToClipboard("background-secret", "sec_01clipboard003", 2);

    // Simulate tab being blurred when expiration hits
    shouldFailWrite = true;
    await vi.advanceTimersByTimeAsync(2000);

    const blurredState = states[states.length - 1];
    expect(blurredState?.pendingFocusPurge).toBe(true);

    // User returns to tab (focus event)
    shouldFailWrite = false;
    for (const listener of listeners["focus"] ?? []) {
      listener();
    }
    // Wait for async return-to-focus clear
    await vi.waitFor(() => {
      expect(states[states.length - 1]?.pendingFocusPurge).toBe(false);
    });

    const restoredState = states[states.length - 1];
    expect(restoredState?.activeSecretId).toBeNull();
    expect(clipboardText).toBe("");

    unsubscribe();
  });

  it("clears clipboard immediately when clearClipboardNow is called", async () => {
    await copySecretToClipboard("manual-clear-secret", "sec_01clipboard004", 30);
    expect(clipboardText).toBe("manual-clear-secret");

    await clearClipboardNow();
    expect(clipboardText).toBe("");
  });
});
