import request from 'supertest';
import mongoose from 'mongoose';
import app from '../../src/app.js';
import { cleanupTestData, createTestUser, generateTestToken } from '../utils/testHelpers.js';

// Test database setup
const setupTestDB = () => {
  beforeAll(async () => {
    const mongoUri = process.env.MONGO_URI_TEST || 'mongodb://localhost:27017/expense-tracker-test';
    await mongoose.connect(mongoUri);
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  afterAll(async () => {
    await cleanupTestData();
    await mongoose.connection.close();
  });
};

// Create authenticated request helper
const createAuthenticatedRequest = async (userData = {}) => {
  const user = await createTestUser(userData);
  const token = generateTestToken(user._id);
  
  return {
    user,
    token,
    request: request(app).set('Authorization', `Bearer ${token}`)
  };
};

// Create admin request helper
const createAdminRequest = async () => {
  return createAuthenticatedRequest({ role: 'admin' });
};

export {
  setupTestDB,
  createAuthenticatedRequest,
  createAdminRequest,
  request
};