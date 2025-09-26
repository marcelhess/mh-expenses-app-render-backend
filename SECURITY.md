# Security Setup Guide

## Environment Variables Setup

This application requires several environment variables to be configured for secure operation. **Never commit the actual `.env` file to version control.**

### Required Environment Variables

1. **Copy the example file:**
   ```bash
   cp .env.example .env
   ```

2. **Configure the following variables in your `.env` file:**

#### Database Configuration
- `MONGO_URI`: Your MongoDB connection string
- `PORT`: Application port (default: 5000)

#### Authentication & Security
- `JWT_SECRET`: A strong, random secret key for JWT tokens (minimum 32 characters)
- `JWT_EXPIRE`: JWT token expiration time (e.g., "30d")
- `JWT_COOKIE_EXPIRE`: Cookie expiration in days
- `API_INTERNAL_TOKEN`: Internal API token for service-to-service communication

#### External APIs
- `GOOGLE_MAPS_API_KEY`: Your Google Maps API key
- `GEMINI_API_KEY`: Your Google Gemini AI API key

#### Email Configuration
- `EMAIL_USERNAME`: SMTP email username
- `EMAIL_PASSWORD`: SMTP email password (use app-specific passwords)
- `FROM_NAME`: Display name for outgoing emails
- `FROM_EMAIL`: From email address

#### Default User Passwords (for seeding)
- `DEFAULT_ADMIN_PASSWORD`: Default admin user password
- `DEFAULT_SALES_PASSWORD`: Default sales user password

### Security Best Practices

1. **Strong Passwords**: Use strong, unique passwords for all accounts
2. **API Keys**: Restrict API keys to specific domains/IPs when possible
3. **JWT Secret**: Generate a cryptographically secure random string
4. **Email Security**: Use app-specific passwords for email services
5. **Environment Isolation**: Use different credentials for development, staging, and production

### Generating Secure Values

#### JWT Secret
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

#### API Internal Token
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Files to Keep Secure

The following files contain sensitive information and should **NEVER** be committed to version control:

- `.env` - Contains all sensitive environment variables
- `logs/` - May contain sensitive application logs
- `reports/` - May contain sensitive user data
- Any files with extensions: `.pem`, `.key`, `.crt`, `.p12`, `.pfx`

### Production Deployment

For production deployments:

1. Use environment variable injection from your hosting platform
2. Enable HTTPS/TLS encryption
3. Use strong, unique passwords for all services
4. Regularly rotate API keys and secrets
5. Monitor logs for security incidents
6. Keep dependencies updated

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by contacting the development team directly rather than opening a public issue.