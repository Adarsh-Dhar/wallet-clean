import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { setAuthTokenGetter, setBaseUrl } from "@workspace/api-client-react";
import { getStoredAuthToken } from "@/lib/auth";

// Prefer an explicit Vite env var for the API base, fall back to localhost:8000 for dev.
setBaseUrl((import.meta as any).env?.VITE_API_BASE ?? "http://localhost:8080");
setAuthTokenGetter(() => getStoredAuthToken());

createRoot(document.getElementById("root")!).render(<App />);
