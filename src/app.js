import express from "express";
import cors from "cors";
import helmet from "helmet";
import swaggerUi from "swagger-ui-express";
import connectDB from "./config/db.js";
import errorHandler from "./middleware/error.js";
import { logger } from "./utils/logger.js";
import morganMiddleware from "./utils/morganLogger.js";
import { generalLimiter } from "./middleware/rateLimiter.js";
import { specs as swaggerSpec } from "./config/swagger.js";
import { initializeEnvironment } from "./utils/envSetup.js";

// Import route files
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import expenseRoutes from "./routes/expenses.js";
import categoryRoutes from "./routes/categories.js";
import reportRoutes from "./routes/reports.js";
import settingRoutes from "./routes/settings.js";
import mapsRoutes from "./routes/maps.js";
import analyticsRoutes from "./routes/analytics.js";
import advancedReportingRoutes from "./routes/advancedReporting.js";
import budgetsRoutes from "./routes/budgets.js";

// Initialize environment variables and setup
initializeEnvironment();

// Create Express app
const app = express();

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy:
      process.env.NODE_ENV === "production" ? undefined : false,
    crossOriginEmbedderPolicy: { policy: "credentialless" },
  })
);

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || "*",
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin",
    "Access-Control-Allow-Headers",
  ],
  exposedHeaders: ["Content-Length", "X-Request-ID"],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Rate limiting
app.use(generalLimiter);

// Logging middleware
if (process.env.NODE_ENV !== 'test') {
  app.use(morganMiddleware);
}

// Connect to database (only if not in test environment)
if (process.env.NODE_ENV !== 'test') {
  connectDB();
}

// API Documentation (only in development or when explicitly enabled)
if (process.env.NODE_ENV !== "production" || process.env.ENABLE_SWAGGER === "true") {
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: "Marcel Expenses API Documentation",
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      filter: true,
      showExtensions: true,
      showCommonExtensions: true,
    }
  }));
}

// API Documentation JSON endpoint
app.get("/api-docs.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(swaggerSpec);
});

// API routes
const API_VERSION = "v1";

app.use(`/api/${API_VERSION}/auth`, authRoutes);
app.use(`/api/${API_VERSION}/users`, userRoutes);
app.use(`/api/${API_VERSION}/expenses`, expenseRoutes);
app.use(`/api/${API_VERSION}/categories`, categoryRoutes);
app.use(`/api/${API_VERSION}/reports`, reportRoutes);
app.use(`/api/${API_VERSION}/settings`, settingRoutes);
app.use(`/api/${API_VERSION}/maps`, mapsRoutes);
app.use(`/api/${API_VERSION}/analytics`, analyticsRoutes);
app.use(`/api/${API_VERSION}/advanced-reports`, advancedReportingRoutes);
app.use(`/api/${API_VERSION}/budgets`, budgetsRoutes);

// Root endpoint
app.get("/", (req, res) => {
  res.json({ message: "Marcel Expenses API is running!" });
});

// 404 handler
app.use((req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
});

// Error handling middleware
app.use(errorHandler);

export default app;