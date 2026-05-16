import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { setBaseUrl } from "@workspace/api-client-react";

// Prefer an explicit Vite env var for the API base, fall back to localhost:8000 for dev.
setBaseUrl((import.meta as any).env?.VITE_API_BASE ?? "http://localhost:8000");

createRoot(document.getElementById("root")!).render(<App />);
