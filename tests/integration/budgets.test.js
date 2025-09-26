import request from 'supertest';
import app from '../../src/app.js';
import User from '../../src/models/User.js';
import Budget from '../../src/models/Budget.js';
import Category from '../../src/models/Category.js';
import { connectTestDB, clearTestDB, disconnectTestDB } from '../setup/testDb.js';

describe('Budget Endpoints', () => {
  let authToken;
  let userId;
  let categoryId;

  beforeAll(async () => {
    await connectTestDB();
  });

  beforeEach(async () => {
    await clearTestDB();

    // Create test user
    const user = await User.create({
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123',
      role: 'user'
    });
    userId = user._id;
    authToken = user.getSignedJwtToken();

    // Create test category
    const category = await Category.create({
      name: 'Transportation',
      description: 'Travel and transport expenses',
      user: userId
    });
    categoryId = category._id;
  });

  afterAll(async () => {
    await disconnectTestDB();
  });

  describe('GET /api/v1/budgets', () => {
    it('should get all budgets for authenticated user', async () => {
      // Create test budgets
      await Budget.create([
        {
          user: userId,
          category: categoryId,
          amount: 1000,
          year: 2024,
          month: 1,
          type: 'monthly'
        },
        {
          user: userId,
          category: categoryId,
          amount: 5000,
          year: 2024,
          type: 'yearly'
        }
      ]);

      const response = await request(app)
        .get('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.data[0]).toHaveProperty('amount');
      expect(response.body.data[0]).toHaveProperty('type');
    });

    it('should filter budgets by year', async () => {
      await Budget.create([
        {
          user: userId,
          category: categoryId,
          amount: 1000,
          year: 2024,
          month: 1,
          type: 'monthly'
        },
        {
          user: userId,
          category: categoryId,
          amount: 1500,
          year: 2023,
          month: 1,
          type: 'monthly'
        }
      ]);

      const response = await request(app)
        .get('/api/v1/budgets?year=2024')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].year).toBe(2024);
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/v1/budgets')
        .expect(401);
    });
  });

  describe('GET /api/v1/budgets/summary', () => {
    it('should get budget summary', async () => {
      await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        spent: 300,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      const response = await request(app)
        .get('/api/v1/budgets/summary')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalBudget');
      expect(response.body.data).toHaveProperty('totalSpent');
    });

    it('should filter summary by period', async () => {
      await Budget.create([
        {
          user: userId,
          category: categoryId,
          amount: 1000,
          spent: 300,
          year: 2024,
          month: 1,
          type: 'monthly'
        },
        {
          user: userId,
          category: categoryId,
          amount: 5000,
          spent: 1500,
          year: 2024,
          type: 'yearly'
        }
      ]);

      const response = await request(app)
        .get('/api/v1/budgets/summary?period=monthly')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.totalBudget).toBe(1000);
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/v1/budgets/summary')
        .expect(401);
    });
  });

  describe('GET /api/v1/budgets/:id', () => {
    it('should get single budget by ID', async () => {
      const budget = await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      const response = await request(app)
        .get(`/api/v1/budgets/${budget._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data._id).toBe(budget._id.toString());
      expect(response.body.data.amount).toBe(1000);
    });

    it('should return 404 for non-existent budget', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .get(`/api/v1/budgets/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });

    it('should not allow access to other users budgets', async () => {
      // Create another user
      const otherUser = await User.create({
        name: 'Other User',
        email: 'other@example.com',
        password: 'password123'
      });

      const budget = await Budget.create({
        user: otherUser._id,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      await request(app)
        .get(`/api/v1/budgets/${budget._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('POST /api/v1/budgets', () => {
    it('should create new budget with valid data', async () => {
      const budgetData = {
        category: categoryId,
        amount: 1500,
        year: 2024,
        month: 3,
        type: 'monthly',
        warningThreshold: 80,
        criticalThreshold: 95
      };

      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send(budgetData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.amount).toBe(1500);
      expect(response.body.data.type).toBe('monthly');
      expect(response.body.data.user).toBe(userId.toString());

      // Verify in database
      const budget = await Budget.findById(response.body.data._id);
      expect(budget).toBeTruthy();
      expect(budget.amount).toBe(1500);
    });

    it('should create yearly budget without month', async () => {
      const budgetData = {
        category: categoryId,
        amount: 12000,
        year: 2024,
        type: 'yearly'
      };

      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send(budgetData)
        .expect(201);

      expect(response.body.data.type).toBe('yearly');
      expect(response.body.data.month).toBeUndefined();
    });

    it('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('required');
    });

    it('should validate amount is positive', async () => {
      const budgetData = {
        category: categoryId,
        amount: -100,
        year: 2024,
        month: 1,
        type: 'monthly'
      };

      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send(budgetData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should validate budget type enum', async () => {
      const budgetData = {
        category: categoryId,
        amount: 1000,
        year: 2024,
        type: 'invalid_type'
      };

      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send(budgetData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should prevent duplicate active budgets', async () => {
      // Create first budget
      await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly',
        isActive: true
      });

      // Try to create duplicate
      const budgetData = {
        category: categoryId,
        amount: 1500,
        year: 2024,
        month: 1,
        type: 'monthly'
      };

      const response = await request(app)
        .post('/api/v1/budgets')
        .set('Authorization', `Bearer ${authToken}`)
        .send(budgetData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('PUT /api/v1/budgets/:id', () => {
    let budgetId;

    beforeEach(async () => {
      const budget = await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly'
      });
      budgetId = budget._id;
    });

    it('should update budget with valid data', async () => {
      const updateData = {
        amount: 1500,
        warningThreshold: 75
      };

      const response = await request(app)
        .put(`/api/v1/budgets/${budgetId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.amount).toBe(1500);
      expect(response.body.data.warningThreshold).toBe(75);

      // Verify in database
      const budget = await Budget.findById(budgetId);
      expect(budget.amount).toBe(1500);
    });

    it('should not allow updating user field', async () => {
      const otherUser = await User.create({
        name: 'Other User',
        email: 'other@example.com',
        password: 'password123'
      });

      const updateData = {
        user: otherUser._id,
        amount: 2000
      };

      const response = await request(app)
        .put(`/api/v1/budgets/${budgetId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      // User should remain unchanged
      expect(response.body.data.user).toBe(userId.toString());
    });

    it('should return 404 for non-existent budget', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .put(`/api/v1/budgets/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ amount: 1500 })
        .expect(404);
    });

    it('should validate updated data', async () => {
      const updateData = {
        amount: -500
      };

      const response = await request(app)
        .put(`/api/v1/budgets/${budgetId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('DELETE /api/v1/budgets/:id', () => {
    let budgetId;

    beforeEach(async () => {
      const budget = await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly'
      });
      budgetId = budget._id;
    });

    it('should delete budget successfully', async () => {
      const response = await request(app)
        .delete(`/api/v1/budgets/${budgetId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify deletion in database
      const budget = await Budget.findById(budgetId);
      expect(budget).toBeNull();
    });

    it('should return 404 for non-existent budget', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .delete(`/api/v1/budgets/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });

    it('should not allow deleting other users budgets', async () => {
      const otherUser = await User.create({
        name: 'Other User',
        email: 'other@example.com',
        password: 'password123'
      });

      const budget = await Budget.create({
        user: otherUser._id,
        category: categoryId,
        amount: 1000,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      await request(app)
        .delete(`/api/v1/budgets/${budget._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      // Verify budget still exists
      const existingBudget = await Budget.findById(budget._id);
      expect(existingBudget).toBeTruthy();
    });
  });

  describe('Budget Calculations', () => {
    it('should calculate remaining amount correctly', async () => {
      const budget = await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        spent: 300,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      const response = await request(app)
        .get(`/api/v1/budgets/${budget._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.remainingAmount).toBe(700);
    });

    it('should calculate usage percentage correctly', async () => {
      const budget = await Budget.create({
        user: userId,
        category: categoryId,
        amount: 1000,
        spent: 250,
        year: 2024,
        month: 1,
        type: 'monthly'
      });

      const response = await request(app)
        .get(`/api/v1/budgets/${budget._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.usagePercentage).toBe(25);
    });
  });
});