import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../../src/models/User.js';
import Category from '../../src/models/Category.js';
import Budget from '../../src/models/Budget.js';
import Expense from '../../src/models/Expense.js';

// Test user data
export const testUserData = {
  name: 'Test User',
  email: 'test@example.com',
  password: 'password123',
  role: 'sales_rep'
};

export const testAdminData = {
  name: 'Test Admin',
  email: 'admin@example.com',
  password: 'admin123',
  role: 'admin'
};

// Create test user
export const createTestUser = async (userData = {}) => {
  const mergedUserData = { ...testUserData, ...userData };
  const user = await User.create(mergedUserData);
  return user;
};

// Generate JWT token for testing
export const generateTestToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '1h' }
  );
};

// Alias for compatibility with integration tests
export const generateJWT = generateTestToken;

// Create authenticated user with token
export const createAuthenticatedUser = async (userData = testUserData) => {
  const user = await createTestUser(userData);
  const token = generateTestToken(user._id);
  
  return { user, token };
};

// Create test category
export const createTestCategory = async (userId, categoryData = {}) => {
  const defaultCategoryData = {
    name: 'Test Category',
    description: 'Test category description',
    color: '#FF5733',
    icon: 'test-icon',
    user: userId
  };
  
  return await Category.create({
    ...defaultCategoryData,
    ...categoryData
  });
};

// Create test budget
export const createTestBudget = async (userId, categoryId, budgetData = {}) => {
  const defaultBudgetData = {
    category: categoryId,
    amount: 1000,
    period: 'monthly',
    startDate: new Date(),
    endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
    user: userId
  };
  
  return await Budget.create({
    ...defaultBudgetData,
    ...budgetData
  });
};

// Create test expense
export const createTestExpense = async (userId, categoryId, expenseData = {}) => {
  const defaultExpenseData = {
    description: 'Test expense',
    amount: 50,
    category: categoryId,
    date: new Date(),
    user: userId,
    paymentMethod: 'cash',
    location: 'Test Location'
  };
  
  return await Expense.create({
    ...defaultExpenseData,
    ...expenseData
  });
};

// Clean up test data
export const cleanupTestData = async () => {
  await Promise.all([
    User.deleteMany({}),
    Category.deleteMany({}),
    Budget.deleteMany({}),
    Expense.deleteMany({})
  ]);
};

// Mock request object
export const mockRequest = (overrides = {}) => ({
  body: {},
  params: {},
  query: {},
  headers: {},
  user: null,
  ...overrides
});

// Mock response object
export const mockResponse = () => {
  const res = {};
  res.status = () => res;
  res.json = () => res;
  res.send = () => res;
  res.cookie = () => res;
  res.clearCookie = () => res;
  return res;
};

// Mock next function
export const mockNext = () => {};

// Test data generators
export const generateTestUsers = (count = 5) => {
  return Array.from({ length: count }, (_, index) => ({
    name: `Test User ${index + 1}`,
    email: `user${index + 1}@example.com`,
    password: 'password123',
    role: 'user'
  }));
};

export const generateTestExpenses = (count = 10, userId, categoryId) => {
  return Array.from({ length: count }, (_, index) => ({
    description: `Test expense ${index + 1}`,
    amount: Math.floor(Math.random() * 1000) + 10,
    category: categoryId,
    date: new Date(Date.now() - Math.floor(Math.random() * 30) * 24 * 60 * 60 * 1000),
    user: userId,
    paymentMethod: ['cash', 'card', 'bank_transfer'][Math.floor(Math.random() * 3)],
    location: `Location ${index + 1}`
  }));
};