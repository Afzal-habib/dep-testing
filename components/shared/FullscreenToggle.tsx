// components/FullscreenToggle.tsx (with tooltip)
'use client';

import { useState, useEffect, forwardRef, useImperativeHandle } from 'react';
import { Maximize2, Minimize2 } from 'lucide-react';

// Changed mode names to concise/descriptive variants
type Mode = 'fullscreen-hide-layout' | 'hide-layout' | 'fullscreen-keep-layout';

interface FullscreenToggleProps {
  mode?: Mode;
  /**
   * CSS selector used to find layout elements to hide. Defaults target common header/sidebar/footer selectors.
   */
  selectors?: string;
  /**
   * Callback fired when fullscreen/layout state changes
   */
  onChange?: (isFullscreen: boolean) => void;
}

export interface FullscreenToggleRef {
  isFullscreen: boolean;
}

const FullscreenToggle = forwardRef<FullscreenToggleRef, FullscreenToggleProps>(
  ({
    mode = 'fullscreen-hide-layout',
    selectors = 'header, footer, aside, [data-role="sidebar"], .sidebar, .header, .footer, .mainCollapserBtn',
    onChange,
  }, ref) => {
    const [isFullscreen, setIsFullscreen] = useState(false);
    const [isLayoutHidden, setIsLayoutHidden] = useState(false);

    useImperativeHandle(ref, () => ({
      isFullscreen,
    }), [isFullscreen]);

  useEffect(() => {
    const hideLayoutElements = () => {
      document.querySelectorAll(selectors).forEach((el) => {
        const element = el as HTMLElement;
        try {
          element.dataset.prevDisplay = element.style.display ?? '';
          element.style.display = 'none';
        } catch (e) {
          // ignore any read-only or other DOM issues
        }
      });
    };

    const restoreLayoutElements = () => {
      document.querySelectorAll(selectors).forEach((el) => {
        const element = el as HTMLElement;
        try {
          if (element.dataset.prevDisplay !== undefined) {
            element.style.display = element.dataset.prevDisplay || '';
            delete element.dataset.prevDisplay;
          } else {
            element.style.display = '';
          }
        } catch (e) {
          // ignore
        }
      });
    };

    // Keep local fullscreen state accurate and handle the fullscreen-hide-layout mode
    const handler = () => {
      const fs = !!document.fullscreenElement;
      setIsFullscreen(fs);
      onChange?.(fs);

      // Only auto-hide/restore for fullscreen-hide-layout mode
      if (mode === 'fullscreen-hide-layout') {
        if (fs) {
          hideLayoutElements();
          setIsLayoutHidden(true);
        } else {
          restoreLayoutElements();
          setIsLayoutHidden(false);
        }
      }
    };

    document.addEventListener('fullscreenchange', handler);

    // on unmount ensure we restore elements if we hid them
    return () => {
      try {
        if (mode === 'fullscreen-hide-layout') {
          restoreLayoutElements();
        }
      } catch (e) {
        // ignore
      }
      document.removeEventListener('fullscreenchange', handler);
    };
    // selectors and mode are intentional dependencies
  }, [selectors, mode]);

  const toggle = async () => {
    // hide-layout: local toggle of layout without touching Fullscreen API
    if (mode === 'hide-layout') {
      if (isLayoutHidden) {
        document.querySelectorAll(selectors).forEach((el) => {
          const element = el as HTMLElement;
          try {
            if (element.dataset.prevDisplay !== undefined) {
              element.style.display = element.dataset.prevDisplay || '';
              delete element.dataset.prevDisplay;
            } else {
              element.style.display = '';
            }
          } catch (e) {
            // ignore
          }
        });
        setIsLayoutHidden(false);
        onChange?.(false);
      } else {
        document.querySelectorAll(selectors).forEach((el) => {
          const element = el as HTMLElement;
          try {
            element.dataset.prevDisplay = element.style.display ?? '';
            element.style.display = 'none';
          } catch (e) {
            // ignore
          }
        });
        setIsLayoutHidden(true);
        onChange?.(true);
      }
      return;
    }

    // For fullscreen modes: request/exit Fullscreen API
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else {
        // If mode === 'fullscreen-keep-layout' we must NOT change layout state here.
        // If previously a hide-layout left elements hidden, we keep that state.
        // For fullscreen-hide-layout we rely on fullscreenchange handler to hide after fullscreen is entered.
        await document.documentElement.requestFullscreen();
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <button
      onClick={toggle}
      className="relative p-2 rounded-lg hover:bg-accent hover:text-accent-foreground transition-all group"
      title={
        mode === 'hide-layout'
          ? isLayoutHidden
            ? 'Restore layout'
            : 'Hide header/sidebar/footer'
          : isFullscreen
          ? 'Exit fullscreen'
          : 'Enter fullscreen'
      }
      aria-label={
        mode === 'hide-layout'
          ? isLayoutHidden
            ? 'Restore layout'
            : 'Hide header/sidebar/footer'
          : isFullscreen
          ? 'Exit fullscreen'
          : 'Enter fullscreen'
      }
    >
      {(mode === 'hide-layout' ? isLayoutHidden : isFullscreen) ? (
        <Minimize2 className="w-5 h-5" />
      ) : (
        <Maximize2 className="w-5 h-5" />
      )}
    </button>
  );
});

export default FullscreenToggle;