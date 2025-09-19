const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("safeAPI", {
  checkPin: (pin) => ipcRenderer.invoke("check-pin", pin),
  setPin: (pin) => ipcRenderer.invoke("set-pin", pin),
  toggleWhitelist: (on) => ipcRenderer.invoke("toggle-whitelist", on),
  addBlockPattern: (pat) => ipcRenderer.invoke("add-block-pattern", pat),
  getBlockPatterns: () => ipcRenderer.invoke("get-block-patterns"),
  removeBlockPattern: (index) => ipcRenderer.invoke("remove-block-pattern", index),
  getWhitelist: () => ipcRenderer.invoke("get-whitelist"),
  addWhitelistItem: (url) => ipcRenderer.invoke("add-whitelist-item", url),
  removeWhitelistItem: (index) => ipcRenderer.invoke("remove-whitelist-item", index),
  getWhitelistMode: () => ipcRenderer.invoke("get-whitelist-mode"),
  getSecurityStats: () => ipcRenderer.invoke("get-security-stats"),
  toggleAIModeration: (enabled) => ipcRenderer.invoke("toggle-ai-moderation", enabled),
  toggleMalwareScan: (enabled) => ipcRenderer.invoke("toggle-malware-scan", enabled),
  toggleGoogleSafety: (enabled) => ipcRenderer.invoke("toggle-google-safety", enabled),
  getFeatureToggles: () => ipcRenderer.invoke("get-feature-toggles")
});