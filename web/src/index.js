import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import Login from "./pages/LoginPage";
import "@fontsource/roboto/300.css"; // Import the font for font-weight: 300
import "@fontsource/roboto/400.css"; // Import the font for font-weight: 400
import "@fontsource/roboto/500.css"; // Import the font for font-weight: 500
import "@fontsource/roboto/700.css"; // Import the font for font-weight: 700
import { ThemeContextProvider } from "./utils/ThemeContext";

console.log("Mode:", process.env.NODE_ENV);
if (process.env.NODE_ENV === "production") {
  console.log = () => {};
  console.error = () => {};
  console.debug = () => {};
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  // <React.StrictMode>
  <ThemeContextProvider>
    <Login />
  </ThemeContextProvider>
  // </React.StrictMode>
);
