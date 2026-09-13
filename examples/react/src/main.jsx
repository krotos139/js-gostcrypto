import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";
import { GostCryptoProvider } from "@gostcrypto/react";
import { App } from "./App.jsx";
import "./styles.css";

const provider = createCryptoProBrowserProvider();

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <GostCryptoProvider provider={provider}>
      <App />
    </GostCryptoProvider>
  </StrictMode>,
);
