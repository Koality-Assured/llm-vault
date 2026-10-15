import type { ClipboardState } from "../types.js";

type ClipboardListener = (state: ClipboardState) => void;

let currentState: ClipboardState = {
  activeSecretId: null,
  secondsRemaining: 0,
  totalDurationSeconds: 30,
  pendingFocusPurge: false,
};

const listeners = new Set<ClipboardListener>();
let intervalTimer: ReturnType<typeof setInterval> | null = null;
let lastBoundWindow: unknown = null;

function notifyListeners(): void {
  for (const listener of listeners) {
    listener({ ...currentState });
  }
}

async function performClipboardClear(): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
    return false;
  }

  try {
    await navigator.clipboard.writeText("");
    return true;
  } catch {
    // Browsers reject writeText with NotAllowedError if the tab/window is not focused
    return false;
  }
}

function setupFocusListeners(): void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return;
  }
  if (lastBoundWindow === window) {
    return;
  }

  const handleReturnToFocus = async () => {
    if (currentState.pendingFocusPurge) {
      const cleared = await performClipboardClear();
      if (cleared) {
        currentState.pendingFocusPurge = false;
        currentState.activeSecretId = null;
        currentState.secondsRemaining = 0;
        if (intervalTimer) {
          clearInterval(intervalTimer);
          intervalTimer = null;
        }
        notifyListeners();
      }
    }
  };

  window.addEventListener("focus", () => {
    void handleReturnToFocus();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      void handleReturnToFocus();
    }
  });

  lastBoundWindow = window;
}

export function subscribeClipboard(listener: ClipboardListener): () => void {
  setupFocusListeners();
  listeners.add(listener);
  listener({ ...currentState });
  return () => {
    listeners.delete(listener);
  };
}

export async function copySecretToClipboard(
  secretValue: string,
  secretId: string,
  durationSeconds: number = 30,
): Promise<boolean> {
  setupFocusListeners();

  if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
    return false;
  }

  try {
    await navigator.clipboard.writeText(secretValue);
  } catch {
    return false;
  }

  if (intervalTimer) {
    clearInterval(intervalTimer);
    intervalTimer = null;
  }

  currentState = {
    activeSecretId: secretId,
    secondsRemaining: durationSeconds,
    totalDurationSeconds: durationSeconds,
    pendingFocusPurge: false,
  };
  notifyListeners();

  intervalTimer = setInterval(async () => {
    if (currentState.secondsRemaining > 1) {
      currentState.secondsRemaining -= 1;
      notifyListeners();
    } else {
      if (intervalTimer) {
        clearInterval(intervalTimer);
        intervalTimer = null;
      }
      currentState.secondsRemaining = 0;

      // Attempt automated clipboard clear
      const cleared = await performClipboardClear();
      if (cleared) {
        currentState.activeSecretId = null;
        currentState.pendingFocusPurge = false;
      } else {
        // Tab was likely blurred/unfocused; queue fallback clear when user returns
        currentState.pendingFocusPurge = true;
      }
      notifyListeners();
    }
  }, 1000);

  return true;
}

export async function clearClipboardNow(): Promise<void> {
  if (intervalTimer) {
    clearInterval(intervalTimer);
    intervalTimer = null;
  }

  await performClipboardClear();
  currentState = {
    activeSecretId: null,
    secondsRemaining: 0,
    totalDurationSeconds: 30,
    pendingFocusPurge: false,
  };
  notifyListeners();
}
