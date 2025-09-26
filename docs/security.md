We are focusing on frontend part of this project

# Security Implementation Documentation

This document outlines the security measures implemented in the Expense Tracker application.

## HTTP Security Headers with Helmet

The application uses the [Helmet](https://helmetjs.github.io/) middleware to set various HTTP headers that help protect against common web vulnerabilities.

### Implemented Headers

Helmet automatically sets the following security headers:

1. **Content-Security-Policy (CSP)**: Controls which resources can be loaded

   - Enabled in production mode
   - Disabled in development mode to allow easier debugging

2. **Strict-Transport-Security (HSTS)**: Forces secure (HTTPS) connections

   - Max age: 15552000 seconds (180 days)

3. **X-Content-Type-Options**: Prevents MIME-type sniffing

   - Set to 'nosniff'

4. **X-Frame-Options**: Prevents clickjacking attacks

   - Set to 'SAMEORIGIN'

5. **X-XSS-Protection**: Provides cross-site scripting protection in older browsers

   - Set to '1; mode=block'

6. **Referrer-Policy**: Controls the information sent in the Referer header

   - Set to 'no-referrer'

7. **Cross-Origin-Embedder-Policy**: Controls which cross-origin resources can be loaded
   - Set to 'credentialless' for better compatibility with embedded resources

### Usage in the Application

The Helmet middleware is configured in `src/server.js`:

```javascript
app.use(
  helmet({
    contentSecurityPolicy:
      process.env.NODE_ENV === "production" ? undefined : false,
    crossOriginEmbedderPolicy: { policy: "credentialless" },
  })
);
```

## CORS Configuration

Cross-Origin Resource Sharing (CORS) is configured to control which domains can access the API.

### Configuration Details

The CORS configuration is defined in `src/server.js`:

```javascript
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
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
```

### Key CORS Settings

1. **Origin**:

   - Controlled via the `CORS_ORIGIN` environment variable
   - Falls back to "\*" (all origins) if not specified
   - In production, this should be set to specific trusted domains

2. **Credentials**:

   - Set to `true` to allow cookies and authentication headers

3. **Exposed Headers**:

   - Explicitly allows frontend access to specific response headers

4. **Options Requests**:
   - Preflight requests return 204 status code
   - Cache preflight results for 24 hours (86400 seconds)

## Secure HTTP Request Logging with Morgan

The application uses [Morgan](https://github.com/expressjs/morgan) for HTTP request logging with security considerations:

### Security Features

1. **Sanitization of Sensitive Data**:

   - Passwords, tokens, and other sensitive data are redacted from logs
   - Implemented in custom Morgan tokens in `src/utils/morganLogger.js`

2. **Controlled Information Exposure**:

   - Request bodies are only logged for POST and PUT requests
   - Empty request bodies are not logged to reduce noise
   - Only logs essential information in production environments

3. **Integration with Winston**:
   - All logs are channeled through Winston for consistent handling
   - Enforces proper log rotation and storage

### Implementation

```javascript
// Custom token to sanitize request bodies
morgan.token("body", (req) => {
  if (req.method === "POST" || req.method === "PUT") {
    const sanitizedBody = { ...req.body };

    // Sanitize sensitive fields if they exist
    if (sanitizedBody.password) sanitizedBody.password = "[REDACTED]";
    if (sanitizedBody.token) sanitizedBody.token = "[REDACTED]";
    if (sanitizedBody.jwt) sanitizedBody.jwt = "[REDACTED]";

    // Only log body if not empty
    return Object.keys(sanitizedBody).length
      ? JSON.stringify(sanitizedBody)
      : "";
  }
  return "";
});
```

## Request Size Limits

To prevent denial-of-service attacks through large payloads, the application limits request sizes:

```javascript
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
```

## Environment-Specific Configuration

For optimal security in production:

1. Set specific origins in the `CORS_ORIGIN` environment variable:

   ```
   CORS_ORIGIN=https://yourfrontend.com,https://admin.yourfrontend.com
   ```

2. Enable Content-Security-Policy in production mode by setting:
   ```
   NODE_ENV=production
   ```

## Additional Security Practices

Beyond HTTP headers and CORS, the application implements:

1. **JWT Authentication**: Secure token-based authentication
2. **Password Hashing**: Passwords are hashed using bcrypt
3. **Request Logging**: All HTTP requests are logged for audit purposes
4. **Error Handling**: Proper error handling to prevent information leakage

## Security Testing

Regularly test the security headers using:

1. [Mozilla Observatory](https://observatory.mozilla.org/)
2. [SecurityHeaders.com](https://securityheaders.com/)
3. [OWASP ZAP](https://www.zaproxy.org/) for comprehensive security testing

## Environment Variables Configuration

⚠️ **SECURITY WARNING**: Never commit actual API keys or secrets to version control!

### Example Environment Variables (.env file)

```bash
# Server Configuration
PORT=5000
MONGO_URI=mongodb://localhost:27017/expense-tracker
BASE_URL=http://localhost:5000

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-here-min-32-chars
JWT_EXPIRE=30d
JWT_COOKIE_EXPIRE=30

# Google Maps API Configuration
GOOGLE_MAPS_API_KEY=your-google-maps-api-key-here

# Gemini AI API Configuration
GEMINI_API_KEY=your-gemini-ai-api-key-here

# Internal API Security
API_INTERNAL_TOKEN=your-secure-internal-api-token-here

# Cost Configuration
DEFAULT_COST_PER_KM=0.70
```

### Security Best Practices for Environment Variables

1. **Never commit actual values** - Use placeholder examples only
2. **Use strong, unique secrets** - Generate cryptographically secure random strings
3. **Rotate keys regularly** - Change API keys and secrets periodically
4. **Limit API key permissions** - Use principle of least privilege
5. **Monitor API usage** - Watch for unusual activity patterns

### Generating Secure Secrets

```bash
# Generate a secure JWT secret (32+ characters)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate a secure API token
node -e "console.log(require('crypto').randomBytes(24).toString('base64'))"
```
