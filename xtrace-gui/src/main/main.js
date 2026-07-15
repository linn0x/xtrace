const {app, BrowserWindow, dialog, ipcMain} = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const {
  DEFAULT_CHROMIUM_APP,
  DEFAULT_LOG_DIR,
  DEFAULT_ASSET_MAX_BYTES,
  startChromiumRun,
  readEventsSince,
  listTraceFiles
} = require("./xtraceProcess");
const {attachAssetContent, readAssetManifest} = require("./xtraceAssets");
const {generateReportForTrace} = require("./xtraceReport");

let mainWindow = null;
let currentRun = null;
let tailTimer = null;
let tailOffset = 0;

if (process.platform === "darwin") {
  app.setActivationPolicy("regular");
  app.dock.show();
}

function createWindow() {
  const showMainWindow = () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.setSkipTaskbar(false);
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }
    mainWindow.show();
    mainWindow.moveTop();
    mainWindow.focus();
    if (process.platform === "darwin") {
      app.dock.show();
      app.focus({steal: true});
      mainWindow.setAlwaysOnTop(true);
      setTimeout(() => {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.setAlwaysOnTop(false);
        }
      }, 250);
    }
  };
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 920,
    minHeight: 620,
    title: "XTrace Workbench",
    show: true,
    webPreferences: {
      preload: path.join(__dirname, "../preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  mainWindow.once("ready-to-show", showMainWindow);
  mainWindow.webContents.once("did-finish-load", showMainWindow);
  setTimeout(showMainWindow, 1000);
  mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
}

function sendStatus(payload) {
  if (mainWindow) {
    mainWindow.webContents.send("xtrace:status", payload);
  }
}

function stopTail() {
  if (tailTimer) {
    clearInterval(tailTimer);
    tailTimer = null;
  }
}

function startTail(tracePath) {
  stopTail();
  tailOffset = 0;
  tailTimer = setInterval(() => {
    const result = readEventsSince(tracePath, tailOffset);
    tailOffset = result.offset;
    if (result.events.length && mainWindow) {
      mainWindow.webContents.send("xtrace:events", result.events);
    }
  }, 500);
}

ipcMain.handle("xtrace:get-defaults", () => ({
  chromiumPath: DEFAULT_CHROMIUM_APP,
  logDir: DEFAULT_LOG_DIR,
  url: "http://127.0.0.1:8765/reverse-smoke.html",
  categories: "reverse,fingerprint",
  captureValues: "full",
  maxValueBytes: 262144,
  captureAssets: "full",
  assetMaxBytes: DEFAULT_ASSET_MAX_BYTES
}));

ipcMain.handle("xtrace:choose-chromium", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile", "openDirectory"],
    message: "Select Chromium.app or Chromium executable"
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle("xtrace:choose-log-dir", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openDirectory", "createDirectory"],
    message: "Select XTrace log directory"
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle("xtrace:start", async (_event, options) => {
  if (currentRun) {
    throw new Error("Chromium is already running");
  }
  currentRun = startChromiumRun(options);
  startTail(currentRun.tracePath);
  currentRun.child.stdout.on("data", (chunk) => sendStatus({stream: "stdout", text: chunk.toString()}));
  currentRun.child.stderr.on("data", (chunk) => sendStatus({stream: "stderr", text: chunk.toString()}));
  currentRun.child.on("exit", (code, signal) => {
    stopTail();
    sendStatus({running: false, code, signal});
    currentRun = null;
  });
  sendStatus({
    running: true,
    tracePath: currentRun.tracePath,
    profilePath: currentRun.profilePath,
    metadataPath: currentRun.metadataPath,
    pid: currentRun.child.pid
  });
  return {
    tracePath: currentRun.tracePath,
    profilePath: currentRun.profilePath,
    metadataPath: currentRun.metadataPath,
    pid: currentRun.child.pid
  };
});

ipcMain.handle("xtrace:stop", async () => {
  if (!currentRun) return false;
  currentRun.child.kill("SIGTERM");
  return true;
});

ipcMain.handle("xtrace:list-logs", (_event, logDir) => listTraceFiles(logDir));

ipcMain.handle("xtrace:read-log", (_event, tracePath) => {
  if (!fs.existsSync(tracePath)) return [];
  return readEventsSince(tracePath, 0).events;
});

ipcMain.handle("xtrace:read-assets", (_event, tracePath) => {
  if (!tracePath || !fs.existsSync(tracePath)) return [];
  return attachAssetContent(tracePath, readAssetManifest(tracePath), {maxBytes: 64 * 1024});
});

ipcMain.handle("xtrace:generate-report", (_event, tracePath) => {
  if (!tracePath || !fs.existsSync(tracePath)) {
    throw new Error("Trace file not found");
  }
  return generateReportForTrace(tracePath);
});

app.whenReady().then(createWindow);
app.on("window-all-closed", () => {
  if (currentRun) {
    currentRun.child.kill("SIGTERM");
  }
  stopTail();
  if (process.platform !== "darwin") {
    app.quit();
  }
});
app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
