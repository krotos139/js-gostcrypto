# React example

This Vite application lists GOST certificates from the CryptoPro browser
extension, signs text or a selected file with a USB token, verifies the
detached CMS signature in JavaScript, and offers the `.p7s` file for download.

```sh
npm install
npm run dev
```

Open the printed local URL in Chrome or Firefox with the CryptoPro extension
enabled. The official `cadesplugin_api.js` is loaded before the React entry
point. For Next.js, Remix, or another SSR framework, construct the CryptoPro
provider only in a client component.
