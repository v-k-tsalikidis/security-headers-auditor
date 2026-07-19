import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { consumeSessionToken } from "./api";
import "./styles.css";

const sessionToken = consumeSessionToken();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App sessionToken={sessionToken} />
  </StrictMode>,
);
