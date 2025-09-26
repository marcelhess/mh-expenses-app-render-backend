import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

let mongoServer;

export const connectTestDB = async () => {
  try {
    // Create an in-memory MongoDB instance
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();

    // Connect to the in-memory database
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('Connected to test database');
  } catch (error) {
    console.error('Error connecting to test database:', error);
    throw error;
  }
};

export const disconnectTestDB = async () => {
  try {
    // Close mongoose connection
    await mongoose.connection.close();
    
    // Stop the in-memory MongoDB instance
    if (mongoServer) {
      await mongoServer.stop();
    }
    
    console.log('Disconnected from test database');
  } catch (error) {
    console.error('Error disconnecting from test database:', error);
    throw error;
  }
};

export const clearTestDB = async () => {
  try {
    const collections = mongoose.connection.collections;
    
    // Clear all collections
    for (const key in collections) {
      const collection = collections[key];
      await collection.deleteMany({});
    }
    
    console.log('Test database cleared');
  } catch (error) {
    console.error('Error clearing test database:', error);
    throw error;
  }
};