export {};
// Inject the pre-built IIFE bundle into the page so tests can access window.JWZ.
// Requires `npm run build:browser` (or `npm run build`) to have been run first.
await new Promise<void>((resolve, reject) => {
  const script = document.createElement('script');
  script.src = '/dist/browser/umd/index.js';
  script.onload = () => resolve();
  script.onerror = () =>
    reject(
      new Error(
        'Could not load /dist/browser/umd/index.js — run `npm run build:browser` first.'
      )
    );
  document.head.appendChild(script);
});
