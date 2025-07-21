// Comprehensive polyfill for telegram (gramJS) package in Node.js environment
import crypto from 'crypto';

// Ensure globals exist before telegram package is loaded
if (typeof global.self === 'undefined') {
  (global as any).self = global;
}

if (typeof global.window === 'undefined') {
  (global as any).window = {
    ...global,
    location: { hostname: 'localhost' },
    navigator: { userAgent: 'Node.js' },
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
    setInterval: global.setInterval,
    clearInterval: global.clearInterval,
  };
}

// Polyfill crypto for telegram package
if (typeof global.crypto === 'undefined') {
  (global as any).crypto = {
    getRandomValues: (buffer: any) => {
      return crypto.randomFillSync(buffer);
    },
    subtle: crypto.webcrypto?.subtle,
  };
}

// Additional browser-like polyfills
if (typeof global.document === 'undefined') {
  (global as any).document = {};
}

if (typeof global.navigator === 'undefined') {
  (global as any).navigator = {
    userAgent: 'Node.js Server',
    platform: 'Node.js',
  };
}

// WebSocket polyfill for telegram package
if (typeof global.WebSocket === 'undefined') {
  try {
    // Try to use ws package if available
    const WebSocket = eval('require')('ws');
    (global as any).WebSocket = WebSocket;
  } catch {
    // If ws not available, provide a stub
    (global as any).WebSocket = class {
      constructor() {
        throw new Error('WebSocket not available in this environment');
      }
    };
  }
}

export {};
