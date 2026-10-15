import React, { useEffect, useState } from "react";
import { AlertTriangle, Clock } from "lucide-react";
import { clearClipboardNow, subscribeClipboard } from "../lib/clipboard.js";
import type { ClipboardState } from "../types.js";

export const ClipboardTimerBar: React.FC = () => {
  const [state, setState] = useState<ClipboardState>({
    activeSecretId: null,
    secondsRemaining: 0,
    totalDurationSeconds: 30,
    pendingFocusPurge: false,
  });

  useEffect(() => {
    return subscribeClipboard(setState);
  }, []);

  if (!state.activeSecretId && !state.pendingFocusPurge) {
    return null;
  }

  const progressPercent = Math.max(
    0,
    Math.min(100, (state.secondsRemaining / state.totalDurationSeconds) * 100),
  );

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 w-full max-w-lg px-4">
      <div className="p-3.5 rounded-2xl bg-neutral-900 border border-neutral-700 shadow-2xl backdrop-blur-md flex flex-col gap-2">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-amber-400 shrink-0 animate-pulse" />
            <span className="font-medium text-neutral-200">Clipboard Purge Timer:</span>
            <span className="font-mono text-amber-400 font-bold">
              {state.secondsRemaining}s remaining
            </span>
          </div>

          <div className="flex items-center gap-2">
            {state.activeSecretId && (
              <span className="font-mono text-[10px] text-neutral-400">
                ({state.activeSecretId})
              </span>
            )}
            <button
              type="button"
              onClick={() => void clearClipboardNow()}
              className="px-2 py-0.5 rounded text-[11px] font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-300 border border-neutral-700 transition"
            >
              Clear Now
            </button>
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-1.5 w-full bg-neutral-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-amber-400 transition-all duration-1000 ease-linear rounded-full"
            style={{ width: `${progressPercent}%` }}
          />
        </div>

        {/* Pending focus purge warning */}
        {state.pendingFocusPurge && (
          <div className="flex items-center gap-1.5 text-[11px] text-amber-300 bg-amber-950/40 p-1.5 rounded-lg border border-amber-800/40">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>
              Tab lost focus before timer expired. Clipboard will wipe automatically on window
              return.
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
