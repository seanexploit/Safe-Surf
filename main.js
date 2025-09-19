const { app, BrowserWindow, session, ipcMain, Menu } = require("electron");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const DATA_DIR = path.join(app.getPath("userData"), "safe-surf-data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Load saved settings if they exist
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");
let settings = {
  blocklist: [/porn/i, /adult/i, /sex/i, /nude/i, /nudity/i, /explicit/i, /xxx/i],
  whitelistMode: false,
  whitelist: ["https://www.google.com/", "https://www.khanacademy.org/", "https://www.wikipedia.org/"],
  adminPinHash: bcrypt.hashSync("1234", 10), // default PIN
  enableAIModeration: true,
  enableMalwareScan: true,
  enableGoogleSafety: true,
  enablePhishingDetection: true
};

// Try to load saved settings
try {
  if (fs.existsSync(SETTINGS_FILE)) {
    const savedSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    
    // Convert regex strings back to RegExp objects
    if (savedSettings.blocklist) {
      savedSettings.blocklist = savedSettings.blocklist.map(pattern => {
        try {
          const match = pattern.match(/^\/(.*)\/([a-z]*)$/);
          if (match) {
            return new RegExp(match[1], match[2]);
          }
          return new RegExp(pattern, "i");
        } catch (e) {
          console.error("Error parsing regex pattern:", pattern);
          return null;
        }
      }).filter(pattern => pattern !== null);
    }
    
    settings = { ...settings, ...savedSettings };
  }
} catch (error) {
  console.error("Error loading settings:", error);
}

let mainWindow;
let securityStats = {
  totalRequests: 0,
  blockedRequests: 0,
  malwareDetected: 0,
  nudityBlocked: 0,
  phishingDetected: 0,
  lastUpdated: new Date()
};

// Malware domain list
const malwareDomains = new Set([
  'malicious.com', 'virus-distribution.net', 'trojan-horse.org',
  'phishing-site.com', 'ransomware-download.com'
]);

// Phishing patterns
const phishingPatterns = [
  "paypal-login\\.com",
  "appleid\\.verify\\.com",
  "facebook-secure\\.login",
  "amazon-account\\.verify",
  "microsoft-account\\.security",
  "bankofamerica\\.login-secure",
  "wellsfargo-onlinebanking\\.com",
  "chase-onlinebanking\\.com",
  "instagram-account\\.verify",
  "netflix-account\\.verify"
];

// Google Safe Browsing API integration (mock)
async function checkGoogleSafeBrowsing(url) {
  if (!settings.enableGoogleSafety) return { safe: true };
  
  try {
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const highRiskIndicators = ['phishing', 'malware', 'unwanted', 'social_engineering'];
    const hasRisk = highRiskIndicators.some(indicator => url.includes(indicator));
    
    return {
      safe: !hasRisk,
      threats: hasRisk ? ['Mock threat detected'] : []
    };
  } catch (error) {
    console.error("Safe Browsing check failed:", error);
    return { safe: true };
  }
}

// AI Content Moderation (simulated)
async function checkAIContentModeration(url) {
  if (!settings.enableAIModeration) return { safe: true };
  
  try {
    await new Promise(resolve => setTimeout(resolve, 200));
    
    const nudityKeywords = ['nude', 'naked', 'explicit', 'porn', 'adult', 'sex'];
    const hasNudity = nudityKeywords.some(keyword => url.toLowerCase().includes(keyword));
    
    return {
      safe: !hasNudity,
      flags: hasNudity ? ['nudity'] : []
    };
  } catch (error) {
    console.error("AI moderation failed:", error);
    return { safe: true };
  }
}

// Malware scanning
async function scanForMalware(url) {
  if (!settings.enableMalwareScan) return { clean: true };
  
  try {
    const domain = new URL(url).hostname;
    const isMalicious = malwareDomains.has(domain);
    
    await new Promise(resolve => setTimeout(resolve, 50));
    
    return {
      clean: !isMalicious,
      threats: isMalicious ? ['Known malware distribution domain'] : []
    };
  } catch (error) {
    console.error("Malware scan failed:", error);
    return { clean: true };
  }
}

// Phishing detection
async function checkForPhishing(url) {
  if (!settings.enablePhishingDetection) return { isPhishing: false };
  
  try {
    for (const pattern of phishingPatterns) {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(url)) {
        securityStats.phishingDetected += 1;
        securityStats.blockedRequests += 1;
        return {
          isPhishing: true,
          pattern: pattern,
          url: url
        };
      }
    }
    
    return { isPhishing: false };
  } catch (error) {
    console.error("Phishing check failed:", error);
    return { isPhishing: false };
  }
}

function saveSettings() {
  try {
    const settingsToSave = {
      ...settings,
      blocklist: settings.blocklist.map(pattern => pattern.toString())
    };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settingsToSave, null, 2));
  } catch (error) {
    console.error("Error saving settings:", error);
  }
}

function logEvent(type, info) {
  const log = { ts: new Date().toISOString(), type, info };
  fs.appendFileSync(path.join(DATA_DIR, "events.log"), JSON.stringify(log) + "\n");
  
  securityStats.totalRequests++;
  if (type.includes('blocked') || type.includes('detected')) {
    securityStats.blockedRequests++;
  }
  if (type.includes('nudity')) {
    securityStats.nudityBlocked++;
  }
  if (type.includes('malware')) {
    securityStats.malwareDetected++;
  }
  securityStats.lastUpdated = new Date();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      enableRemoteModule: false,
      sandbox: false
    }
  });

  Menu.setApplicationMenu(null);

  const ses = session.defaultSession;

  // Intercept requests with enhanced security checks
  ses.webRequest.onBeforeRequest({ urls: ["*://*/*"] }, async (details, callback) => {
    const url = details.url || "";
    
    securityStats.totalRequests++;

    // Whitelist enforcement
    if (settings.whitelistMode) {
      const allowed = settings.whitelist.some((w) => url.startsWith(w));
      if (!allowed) {
        logEvent("blocked-whitelist", url);
        securityStats.blockedRequests++;
        return callback({ cancel: true });
      }
    }

    // Blocklist patterns
    for (const re of settings.blocklist) {
      if (re.test(url)) {
        logEvent("blocked-pattern", url);
        securityStats.blockedRequests++;
        return callback({ cancel: true });
      }
    }

    // Phishing detection
    const phishingResult = await checkForPhishing(url);
    if (phishingResult.isPhishing) {
      logEvent("blocked-phishing", { url, pattern: phishingResult.pattern });
      securityStats.blockedRequests++;
      return callback({ cancel: true });
    }

    // Malware scanning
    const malwareResult = await scanForMalware(url);
    if (!malwareResult.clean) {
      logEvent("blocked-malware", { url, threats: malwareResult.threats });
      securityStats.malwareDetected++;
      securityStats.blockedRequests++;
      return callback({ cancel: true });
    }

    // Google Safe Browsing check
    const safeBrowsingResult = await checkGoogleSafeBrowsing(url);
    if (!safeBrowsingResult.safe) {
      logEvent("blocked-google-safety", { url, threats: safeBrowsingResult.threats });
      securityStats.blockedRequests++;
      return callback({ cancel: true });
    }

    // AI Content Moderation
    const aiResult = await checkAIContentModeration(url);
    if (!aiResult.safe) {
      logEvent("blocked-ai", { url, flags: aiResult.flags });
      securityStats.nudityBlocked++;
      securityStats.blockedRequests++;
      return callback({ cancel: true });
    }

    // Enforce HTTPS
    if (url.startsWith("http://")) {
      const httpsUrl = url.replace("http://", "https://");
      logEvent("redirect-https", url);
      return callback({ redirectURL: httpsUrl });
    }

    // Force SafeSearch for Google
    if (/google\.[a-z]+\/search/.test(url) && !/safe=/.test(url)) {
      const separator = url.includes("?") ? "&" : "?";
      const newUrl = url + separator + "safe=active";
      logEvent("rewrite-safesearch", url);
      return callback({ redirectURL: newUrl });
    }
    
    // Force SafeSearch for Bing
    if (/bing\./.test(url) && /search/.test(url) && !/adlt=/.test(url)) {
      const separator = url.includes("?") ? "&" : "?";
      const newUrl = url + separator + "adlt=strict";
      logEvent("rewrite-safesearch", url);
      return callback({ redirectURL: newUrl });
    }

    return callback({ cancel: false });
  });

  // Additional response handler for content scanning
  ses.webRequest.onHeadersReceived({ urls: ["*://*/*"] }, (details, callback) => {
    if (details.responseHeaders['content-type'] && 
        details.responseHeaders['content-type'][0].startsWith('image/')) {
      
      const url = details.url;
      const nudityIndicators = ['nude', 'naked', 'explicit', 'adult'];
      const hasNudityIndicator = nudityIndicators.some(indicator => 
        url.toLowerCase().includes(indicator)
      );
      
      if (hasNudityIndicator) {
        logEvent("blocked-nudity-image", url);
        securityStats.nudityBlocked++;
        securityStats.blockedRequests++;
        return callback({ cancel: true });
      }
    }
    
    callback({ cancel: false, responseHeaders: details.responseHeaders });
  });

  // Block downloads
  ses.on("will-download", (event, item) => {
    event.preventDefault();
    logEvent("download-blocked", item.getURL());
    securityStats.blockedRequests++;
  });

  // Prevent popups unless whitelisted
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    for (const w of settings.whitelist) {
      if (url.startsWith(w)) return { action: "allow" };
    }
    logEvent("blocked-popup", url);
    securityStats.blockedRequests++;
    return { action: "deny" };
  });

  // Handle certificate errors
  ses.setCertificateVerifyProc((request, callback) => {
    callback(0);
  });

  mainWindow.loadFile("index.html");

  // Open DevTools for development
  // mainWindow.webContents.openDevTools();

  app.on('before-quit', () => {
    saveSettings();
  });
}

// IPC handlers for admin panel
ipcMain.handle("check-pin", (evt, pin) => {
  return bcrypt.compareSync(String(pin), settings.adminPinHash);
});

ipcMain.handle("set-pin", (evt, pin) => {
  settings.adminPinHash = bcrypt.hashSync(String(pin), 10);
  saveSettings();
  return true;
});

ipcMain.handle("toggle-whitelist", (evt, enabled) => {
  settings.whitelistMode = !!enabled;
  saveSettings();
  return settings.whitelistMode;
});

ipcMain.handle("add-block-pattern", (evt, pattern) => {
  try {
    const re = new RegExp(pattern, "i");
    settings.blocklist.push(re);
    saveSettings();
    return true;
  } catch (e) {
    return false;
  }
});

ipcMain.handle("get-block-patterns", () => {
  return settings.blocklist.map(pattern => pattern.source);
});

ipcMain.handle("remove-block-pattern", (evt, index) => {
  if (index >= 0 && index < settings.blocklist.length) {
    settings.blocklist.splice(index, 1);
    saveSettings();
    return true;
  }
  return false;
});

ipcMain.handle("get-whitelist", () => {
  return settings.whitelist;
});

ipcMain.handle("add-whitelist-item", (evt, url) => {
  if (url && !settings.whitelist.includes(url)) {
    settings.whitelist.push(url);
    saveSettings();
    return true;
  }
  return false;
});

ipcMain.handle("remove-whitelist-item", (evt, index) => {
  if (index >= 0 && index < settings.whitelist.length) {
    settings.whitelist.splice(index, 1);
    saveSettings();
    return true;
  }
  return false;
});

ipcMain.handle("get-whitelist-mode", () => {
  return settings.whitelistMode;
});

ipcMain.handle("get-security-stats", () => {
  return securityStats;
});

ipcMain.handle("toggle-ai-moderation", (evt, enabled) => {
  settings.enableAIModeration = !!enabled;
  saveSettings();
  return settings.enableAIModeration;
});

ipcMain.handle("toggle-malware-scan", (evt, enabled) => {
  settings.enableMalwareScan = !!enabled;
  saveSettings();
  return settings.enableMalwareScan;
});

ipcMain.handle("toggle-google-safety", (evt, enabled) => {
  settings.enableGoogleSafety = !!enabled;
  saveSettings();
  return settings.enableGoogleSafety;
});

ipcMain.handle("toggle-phishing-detection", (evt, enabled) => {
  settings.enablePhishingDetection = !!enabled;
  saveSettings();
  return settings.enablePhishingDetection;
});

ipcMain.handle("get-feature-toggles", () => {
  return {
    enableAIModeration: settings.enableAIModeration,
    enableMalwareScan: settings.enableMalwareScan,
    enableGoogleSafety: settings.enableGoogleSafety,
    enablePhishingDetection: settings.enablePhishingDetection
  };
});

ipcMain.handle("get-phishing-patterns", () => {
  return phishingPatterns;
});

// App event handlers
app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// Security: Prevent navigation to external protocols
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      event.preventDefault();
    }
  });
});