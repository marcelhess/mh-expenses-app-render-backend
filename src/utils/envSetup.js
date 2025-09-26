import dotenv from "dotenv";
import crypto from "crypto";

/**
 * Initialize environment variables and set up default values
 * This function handles the common environment setup logic
 */
export function initializeEnvironment() {
  // Load environment variables
  dotenv.config();

  // Generate internal API token if not present
  if (!process.env.API_INTERNAL_TOKEN) {
    const internalToken = crypto.randomBytes(32).toString("hex");
    process.env.API_INTERNAL_TOKEN = internalToken;
    
    // Only show warnings in server.js context (when not in test mode)
    if (process.env.NODE_ENV !== 'test') {
      console.log(
        "\x1b[33m%s\x1b[0m",
        "WARNING: API_INTERNAL_TOKEN not set in environment"
      );
      console.log("\x1b[33m%s\x1b[0m", `Using generated token: ${internalToken}`);
      console.log(
        "\x1b[33m%s\x1b[0m",
        "Add this to your .env file for persistent internal API access"
      );
    }
  }

  // Set base URL for internal API calls
  if (!process.env.BASE_URL) {
    const port = process.env.PORT || 5000;
    process.env.BASE_URL = `http://localhost:${port}`;
    
    // Only show warnings in server.js context (when not in test mode)
    if (process.env.NODE_ENV !== 'test') {
      console.log("\x1b[33m%s\x1b[0m", "WARNING: BASE_URL not set in environment");
      console.log("\x1b[33m%s\x1b[0m", `Using default: ${process.env.BASE_URL}`);
    }
  }
}