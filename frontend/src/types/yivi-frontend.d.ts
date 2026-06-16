declare module '@privacybydesign/yivi-frontend' {
  // Minimal typings for runtime usage in this demo
  interface SessionConfig {
    url: string;
    pointer?: unknown;
    sessionPtr?: unknown;
    start?: unknown;
    result?: boolean | unknown;
  }
  interface PopupOptions {
    language?: string;
    session: SessionConfig;
  }
  interface PopupInstance {
    start: () => Promise<void>;
    close?: () => void;
  }
  export function newPopup(opts: PopupOptions): PopupInstance;

  // Minimal typing for the embedded web widget
  interface WebOptions {
    debugging?: boolean;
    element: string | HTMLElement;
    language?: string;
    session: {
      url: string;
      start: unknown;
      mapping?: unknown;
      result: unknown;
    };
  }
  interface WebInstance {
    start: () => Promise<unknown>;
    abort?: () => void;
  }
  export function newWeb(opts: WebOptions): WebInstance;
}
