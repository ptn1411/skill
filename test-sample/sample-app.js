// Sample artifact for testing authorized-artifact-auditor ONLY.
// This is a deliberately insecure, fake Electron-style snippet.
// It contains no real secret: EXAMPLE-TOKEN-NOT-REAL is a placeholder.
const { BrowserWindow } = require("electron");

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  win.loadURL("https://example.invalid/");
  return win;
}

const CONFIG = {
  apiTokenPlaceholder: "EXAMPLE-TOKEN-NOT-REAL",
};

module.exports = { createWindow, CONFIG };
