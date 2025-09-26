import User from '../../src/models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createTestUser, testUserData } from '../utils/testHelpers.js';

describe('User Model', () => {
  describe('User Schema Validation', () => {
    test('should create a valid user', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      };

      const user = new User(userData);
      const savedUser = await user.save();

      expect(savedUser._id).toBeDefined();
      expect(savedUser.name).toBe(userData.name);
      expect(savedUser.email).toBe(userData.email);
      expect(savedUser.role).toBe('sales_rep'); // default role
      expect(savedUser.status).toBe('active'); // default status
      expect(savedUser.createdAt).toBeDefined();
      expect(savedUser.updatedAt).toBeDefined();
    });

    test('should require name field', async () => {
      const userData = {
        email: 'john@example.com',
        password: 'password123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Please add a name');
    });

    test('should require email field', async () => {
      const userData = {
        name: 'John Doe',
        password: 'password123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Please add an email');
    });

    test('should require password field', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Please add a password');
    });

    test('should validate email format', async () => {
      const userData = {
        name: 'John Doe',
        email: 'invalid-email',
        password: 'password123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Please add a valid email');
    });

    test('should enforce minimum password length', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: '123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Password must be at least 6 characters');
    });

    test('should enforce maximum name length', async () => {
      const userData = {
        name: 'a'.repeat(51), // 51 characters
        email: 'john@example.com',
        password: 'password123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow('Name cannot be more than 50 characters');
    });

    test('should enforce unique email constraint', async () => {
      const userData1 = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      };

      const userData2 = {
        name: 'Jane Doe',
        email: 'john@example.com', // same email
        password: 'password456'
      };

      await User.create(userData1);
      
      await expect(User.create(userData2)).rejects.toThrow();
    });

    test('should validate role enum values', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123',
        role: 'invalid_role'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow();
    });

    test('should validate status enum values', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123',
        status: 'invalid_status'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow();
    });
  });

  describe('Password Hashing', () => {
    test('should hash password before saving', async () => {
      const plainPassword = 'password123';
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: plainPassword
      };

      const user = new User(userData);
      await user.save();

      // Fetch user with password field
      const savedUser = await User.findById(user._id).select('+password');
      
      expect(savedUser.password).not.toBe(plainPassword);
      expect(savedUser.password).toMatch(/^\$2[ayb]\$.{56}$/); // bcrypt hash pattern
    });

    test('should not rehash password if not modified', async () => {
      const user = await createTestUser();
      const originalPassword = await User.findById(user._id).select('+password');
      
      // Update user without changing password
      user.name = 'Updated Name';
      await user.save();
      
      const updatedUser = await User.findById(user._id).select('+password');
      expect(updatedUser.password).toBe(originalPassword.password);
    });
  });

  describe('JWT Token Generation', () => {
    test('should generate valid JWT token', async () => {
      process.env.JWT_SECRET = 'test-secret';
      process.env.JWT_EXPIRE = '30d';
      
      const user = await createTestUser();
      const token = user.getSignedJwtToken();
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.id).toBe(user._id.toString());
    });

    test('should include user ID in token payload', async () => {
      process.env.JWT_SECRET = 'test-secret';
      
      const user = await createTestUser();
      const token = user.getSignedJwtToken();
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.id).toBe(user._id.toString());
    });
  });

  describe('Password Matching', () => {
    test('should match correct password', async () => {
      const plainPassword = 'password123';
      const user = await createTestUser({ ...testUserData, password: plainPassword });
      
      const userWithPassword = await User.findById(user._id).select('+password');
      const isMatch = await userWithPassword.matchPassword(plainPassword);
      
      expect(isMatch).toBe(true);
    });

    test('should not match incorrect password', async () => {
      const plainPassword = 'password123';
      const wrongPassword = 'wrongpassword';
      const user = await createTestUser({ ...testUserData, password: plainPassword });
      
      const userWithPassword = await User.findById(user._id).select('+password');
      const isMatch = await userWithPassword.matchPassword(wrongPassword);
      
      expect(isMatch).toBe(false);
    });

    test('should handle empty password', async () => {
      const user = await createTestUser();
      const userWithPassword = await User.findById(user._id).select('+password');
      
      const isMatch = await userWithPassword.matchPassword('');
      expect(isMatch).toBe(false);
    });
  });

  describe('User Roles and Status', () => {
    test('should create admin user', async () => {
      const adminData = {
        name: 'Admin User',
        email: 'admin@example.com',
        password: 'password123',
        role: 'admin'
      };

      const user = await User.create(adminData);
      expect(user.role).toBe('admin');
    });

    test('should create inactive user', async () => {
      const userData = {
        name: 'Inactive User',
        email: 'inactive@example.com',
        password: 'password123',
        status: 'inactive'
      };

      const user = await User.create(userData);
      expect(user.status).toBe('inactive');
    });
  });

  describe('User Queries', () => {
    test('should find user by email', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      };

      await User.create(userData);
      const foundUser = await User.findOne({ email: userData.email });
      
      expect(foundUser).toBeDefined();
      expect(foundUser.email).toBe(userData.email);
    });

    test('should exclude password by default', async () => {
      const user = await createTestUser();
      const foundUser = await User.findById(user._id);
      
      expect(foundUser.password).toBeUndefined();
    });

    test('should include password when explicitly selected', async () => {
      const user = await createTestUser();
      const foundUser = await User.findById(user._id).select('+password');
      
      expect(foundUser.password).toBeDefined();
    });
  });
});