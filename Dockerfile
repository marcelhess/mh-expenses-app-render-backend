# Use the official Node.js 18 image as base
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install all dependencies (including dev dependencies for development)
RUN npm ci

# Copy the rest of the application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Create reports/temp directory
RUN mkdir -p reports/temp

# Expose the port the app runs on
EXPOSE 5000

# Create a non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S backend -u 1001

# Change ownership of the app directory
RUN chown -R backend:nodejs /app
USER backend

# Start the application in development mode
CMD ["npm", "run", "dev"]