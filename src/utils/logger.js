const fs = require("fs");
const path = require("path");

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";

// Simple file writer
const writeToFile = (filename, message) => {
  const filePath = path.join(logsDir, filename);
  const timestamp = new Date().toISOString();
  const logMessage = `${timestamp} - ${message}\n`;
  
  try {
    fs.appendFileSync(filePath, logMessage);
  } catch (error) {
    console.error("Failed to write to log file:", error.message);
  }
};

// Simple logger object
const logger = {
  info: (message, meta = {}) => {
    const logData = {
      level: "info",
      message,
      timestamp: new Date().toISOString(),
      ...meta,
    };
    
    const logString = JSON.stringify(logData);
    
    // Console output
    if (!IS_PRODUCTION) {
      console.log(`ℹ️  [INFO] ${message}`, meta);
    }
    
    // File output
    writeToFile("combined.log", logString);
  },

  warn: (message, meta = {}) => {
    const logData = {
      level: "warn",
      message,
      timestamp: new Date().toISOString(),
      ...meta,
    };
    
    const logString = JSON.stringify(logData);
    
    // Console output
    console.warn(`⚠️  [WARN] ${message}`, meta);
    
    // File output
    writeToFile("combined.log", logString);
  },

  error: (message, meta = {}) => {
    const logData = {
      level: "error",
      message,
      timestamp: new Date().toISOString(),
      ...meta,
    };
    
    const logString = JSON.stringify(logData);
    
    // Console output
    console.error(`❌ [ERROR] ${message}`, meta);
    
    // File output
    writeToFile("error.log", logString);
    writeToFile("combined.log", logString);
  },

  debug: (message, meta = {}) => {
    if (IS_PRODUCTION) return; // Skip debug logs in production
    
    const logData = {
      level: "debug",
      message,
      timestamp: new Date().toISOString(),
      ...meta,
    };
    
    const logString = JSON.stringify(logData);
    
    // Console output
    console.log(`🔍 [DEBUG] ${message}`, meta);
    
    // File output
    writeToFile("combined.log", logString);
  },
};

module.exports = logger;
