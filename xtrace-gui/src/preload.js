const {contextBridge, ipcRenderer} = require("electron");

contextBridge.exposeInMainWorld("xtrace", {
  getDefaults: () => ipcRenderer.invoke("xtrace:get-defaults"),
  chooseChromium: () => ipcRenderer.invoke("xtrace:choose-chromium"),
  chooseLogDir: () => ipcRenderer.invoke("xtrace:choose-log-dir"),
  start: (options) => ipcRenderer.invoke("xtrace:start", options),
  stop: () => ipcRenderer.invoke("xtrace:stop"),
  listLogs: (logDir) => ipcRenderer.invoke("xtrace:list-logs", logDir),
  readLog: (tracePath) => ipcRenderer.invoke("xtrace:read-log", tracePath),
  readAssets: (tracePath) => ipcRenderer.invoke("xtrace:read-assets", tracePath),
  generateReport: (tracePath) => ipcRenderer.invoke("xtrace:generate-report", tracePath),
  onStatus: (callback) => {
    ipcRenderer.on("xtrace:status", (_event, payload) => callback(payload));
  },
  onEvents: (callback) => {
    ipcRenderer.on("xtrace:events", (_event, events) => callback(events));
  }
});
