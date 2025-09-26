import app from "./app.js";
import connectDB from "./config/db.js";
import { logger } from "./utils/logger.js";
import { initializeEnvironment } from "./utils/envSetup.js";

// Initialize environment variables and setup
initializeEnvironment();

// Connect to database
connectDB();

// Process error handling
process.on("uncaughtException", (error) => {
  logger.error({
    message: "Uncaught Exception",
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error({
    message: "Unhandled Rejection",
    reason: reason,
    promise: promise,
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(
    `Server running in ${
      process.env.NODE_ENV || "development"
    } mode on port ${PORT}`
  );
});
