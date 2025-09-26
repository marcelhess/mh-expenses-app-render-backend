import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load test environment variables
dotenv.config({ path: '.env.test' });

let mongoServer;

// Global setup before all tests
beforeAll(async () => {
  // Create in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  console.log('Connected to in-memory MongoDB for testing');
});

// Clean up after each test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
});

// Global cleanup after all tests
afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  await mongoServer.stop();
  console.log('Disconnected from in-memory MongoDB');
});

// Mock console.log in tests to reduce noise
global.console = {
  ...console,
  log: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};