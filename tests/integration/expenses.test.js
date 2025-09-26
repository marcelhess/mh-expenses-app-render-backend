import request from 'supertest';
import app from '../../src/app.js';
import User from '../../src/models/User.js';
import Category from '../../src/models/Category.js';
import Expense from '../../src/models/Expense.js';
import { createTestUser, generateJWT } from '../utils/testHelpers.js';
import { connectTestDB, clearTestDB, disconnectTestDB } from '../setup/testDb.js';

describe('Expenses Integration Tests', () => {
  let testUser;
  let authToken;
  let testCategory;

  beforeAll(async () => {
    await connectTestDB();
  });

  beforeEach(async () => {
    await clearTestDB();
    testUser = await createTestUser();
    authToken = generateJWT(testUser._id);
    testCategory = await Category.create({
      name: 'Transportation',
      description: 'Travel expenses'
    });
  });

  describe('GET /api/v1/expenses', () => {
    beforeEach(async () => {
      // Create test expenses
      await Expense.create([
        {
          user: testUser._id,
          category: testCategory._id,
          startingPoint: 'Home',
          destinationPoint: 'Office',
          distance: 10,
          costPerKm: 2.5,
          totalCost: 25,
          journeyDate: new Date('2024-01-15'),
          status: 'completed'
        },
        {
          user: testUser._id,
          category: testCategory._id,
          startingPoint: 'Office',
          destinationPoint: 'Client',
          distance: 20,
          costPerKm: 3.0,
          totalCost: 60,
          journeyDate: new Date('2024-01-20'),
          status: 'pending'
        }
      ]);
    });

    test('should get all expenses for authenticated user', async () => {
      const response = await request(app)
        .get('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.pagination).toBeDefined();
      expect(response.body.pagination.total).toBe(2);
      expect(response.body.data[0]).toHaveProperty('startingPoint');
      expect(response.body.data[0]).toHaveProperty('destinationPoint');
      expect(response.body.data[0]).toHaveProperty('totalCost');
    });

    test('should filter expenses by category', async () => {
      const response = await request(app)
        .get(`/api/v1/expenses?category=${testCategory._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.data[0].category).toBe(testCategory._id.toString());
    });

    test('should filter expenses by status', async () => {
      const response = await request(app)
        .get('/api/v1/expenses?status=completed')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].status).toBe('completed');
    });

    test('should filter expenses by date range', async () => {
      const response = await request(app)
        .get('/api/v1/expenses?startDate=2024-01-01&endDate=2024-01-16')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(1);
      expect(new Date(response.body.data[0].journeyDate)).toEqual(new Date('2024-01-15'));
    });

    test('should paginate expenses correctly', async () => {
      const response = await request(app)
        .get('/api/v1/expenses?page=1&limit=1')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(1);
      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(1);
      expect(response.body.pagination.total).toBe(2);
      expect(response.body.pagination.pages).toBe(2);
    });

    test('should sort expenses by date descending by default', async () => {
      const response = await request(app)
        .get('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      
      const dates = response.body.data.map(expense => new Date(expense.journeyDate));
      expect(dates[0]).toEqual(new Date('2024-01-20')); // Most recent first
      expect(dates[1]).toEqual(new Date('2024-01-15'));
    });

    test('should not get expenses without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/expenses')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Not authorized');
    });

    test('should only return expenses for authenticated user', async () => {
      // Create another user and expense
      const otherUser = await createTestUser({
        name: 'Other User',
        email: 'other@example.com',
        phone: '+233987654321'
      });

      await Expense.create({
        user: otherUser._id,
        category: testCategory._id,
        startingPoint: 'Other Home',
        destinationPoint: 'Other Office',
        distance: 15,
        costPerKm: 2.0,
        totalCost: 30,
        journeyDate: new Date('2024-01-25')
      });

      const response = await request(app)
        .get('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2); // Only testUser's expenses
      expect(response.body.data.every(expense => expense.user === testUser._id.toString())).toBe(true);
    });
  });

  describe('GET /api/v1/expenses/:id', () => {
    let testExpense;

    beforeEach(async () => {
      testExpense = await Expense.create({
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        journeyDate: new Date('2024-01-15')
      });
    });

    test('should get expense by ID for authenticated user', async () => {
      const response = await request(app)
        .get(`/api/v1/expenses/${testExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(testExpense._id.toString());
      expect(response.body.data.startingPoint).toBe('Home');
      expect(response.body.data.destinationPoint).toBe('Office');
      expect(response.body.data.totalCost).toBe(25);
    });

    test('should not get expense with invalid ID', async () => {
      const response = await request(app)
        .get('/api/v1/expenses/invalid-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should not get non-existent expense', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .get(`/api/v1/expenses/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');
    });

    test('should not get expense belonging to another user', async () => {
      const otherUser = await createTestUser({
        name: 'Other User',
        email: 'other@example.com',
        phone: '+233987654321'
      });

      const otherExpense = await Expense.create({
        user: otherUser._id,
        category: testCategory._id,
        startingPoint: 'Other Home',
        destinationPoint: 'Other Office',
        distance: 15,
        costPerKm: 2.0,
        totalCost: 30,
        journeyDate: new Date('2024-01-25')
      });

      const response = await request(app)
        .get(`/api/v1/expenses/${otherExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');
    });
  });

  describe('POST /api/v1/expenses', () => {
    test('should create expense successfully', async () => {
      const expenseData = {
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        journeyDate: '2024-01-15',
        notes: 'Daily commute'
      };

      const response = await request(app)
        .post('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .send(expenseData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.startingPoint).toBe(expenseData.startingPoint);
      expect(response.body.data.destinationPoint).toBe(expenseData.destinationPoint);
      expect(response.body.data.distance).toBe(expenseData.distance);
      expect(response.body.data.costPerKm).toBe(expenseData.costPerKm);
      expect(response.body.data.totalCost).toBe(25); // calculated automatically
      expect(response.body.data.user).toBe(testUser._id.toString());

      // Verify expense was created in database
      const expense = await Expense.findById(response.body.data.id);
      expect(expense).toBeTruthy();
      expect(expense.totalCost).toBe(25);
    });

    test('should not create expense with missing required fields', async () => {
      const expenseData = {
        startingPoint: 'Home',
        destinationPoint: 'Office'
        // missing category, distance, costPerKm
      };

      const response = await request(app)
        .post('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .send(expenseData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should not create expense with invalid category', async () => {
      const expenseData = {
        category: 'invalid-category-id',
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        journeyDate: '2024-01-15'
      };

      const response = await request(app)
        .post('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .send(expenseData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should not create expense with negative distance', async () => {
      const expenseData = {
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: -10,
        costPerKm: 2.5,
        journeyDate: '2024-01-15'
      };

      const response = await request(app)
        .post('/api/v1/expenses')
        .set('Authorization', `Bearer ${authToken}`)
        .send(expenseData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('distance');
    });

    test('should not create expense without authentication', async () => {
      const expenseData = {
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        journeyDate: '2024-01-15'
      };

      const response = await request(app)
        .post('/api/v1/expenses')
        .send(expenseData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Not authorized');
    });
  });

  describe('PUT /api/v1/expenses/:id', () => {
    let testExpense;

    beforeEach(async () => {
      testExpense = await Expense.create({
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        journeyDate: new Date('2024-01-15')
      });
    });

    test('should update expense successfully', async () => {
      const updateData = {
        startingPoint: 'Updated Home',
        destinationPoint: 'Updated Office',
        distance: 15,
        costPerKm: 3.0,
        notes: 'Updated notes'
      };

      const response = await request(app)
        .put(`/api/v1/expenses/${testExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.startingPoint).toBe(updateData.startingPoint);
      expect(response.body.data.destinationPoint).toBe(updateData.destinationPoint);
      expect(response.body.data.distance).toBe(updateData.distance);
      expect(response.body.data.costPerKm).toBe(updateData.costPerKm);
      expect(response.body.data.totalCost).toBe(45); // recalculated: 15 * 3.0
      expect(response.body.data.notes).toBe(updateData.notes);

      // Verify update in database
      const updatedExpense = await Expense.findById(testExpense._id);
      expect(updatedExpense.totalCost).toBe(45);
    });

    test('should not update expense with invalid data', async () => {
      const updateData = {
        distance: -5 // invalid negative distance
      };

      const response = await request(app)
        .put(`/api/v1/expenses/${testExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('distance');
    });

    test('should not update non-existent expense', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011';
      const updateData = {
        notes: 'Updated notes'
      };

      const response = await request(app)
        .put(`/api/v1/expenses/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');
    });

    test('should not update expense belonging to another user', async () => {
      const otherUser = await createTestUser({
        name: 'Other User',
        email: 'other@example.com',
        phone: '+233987654321'
      });

      const otherExpense = await Expense.create({
        user: otherUser._id,
        category: testCategory._id,
        startingPoint: 'Other Home',
        destinationPoint: 'Other Office',
        distance: 15,
        costPerKm: 2.0,
        totalCost: 30,
        journeyDate: new Date('2024-01-25')
      });

      const updateData = {
        notes: 'Trying to update other user expense'
      };

      const response = await request(app)
        .put(`/api/v1/expenses/${otherExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');
    });
  });

  describe('DELETE /api/v1/expenses/:id', () => {
    let testExpense;

    beforeEach(async () => {
      testExpense = await Expense.create({
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        journeyDate: new Date('2024-01-15')
      });
    });

    test('should delete expense successfully', async () => {
      const response = await request(app)
        .delete(`/api/v1/expenses/${testExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual({});

      // Verify expense was deleted from database
      const deletedExpense = await Expense.findById(testExpense._id);
      expect(deletedExpense).toBeNull();
    });

    test('should not delete non-existent expense', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011';

      const response = await request(app)
        .delete(`/api/v1/expenses/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');
    });

    test('should not delete expense belonging to another user', async () => {
      const otherUser = await createTestUser({
        name: 'Other User',
        email: 'other@example.com',
        phone: '+233987654321'
      });

      const otherExpense = await Expense.create({
        user: otherUser._id,
        category: testCategory._id,
        startingPoint: 'Other Home',
        destinationPoint: 'Other Office',
        distance: 15,
        costPerKm: 2.0,
        totalCost: 30,
        journeyDate: new Date('2024-01-25')
      });

      const response = await request(app)
        .delete(`/api/v1/expenses/${otherExpense._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not found');

      // Verify expense still exists
      const stillExists = await Expense.findById(otherExpense._id);
      expect(stillExists).toBeTruthy();
    });

    test('should not delete expense without authentication', async () => {
      const response = await request(app)
        .delete(`/api/v1/expenses/${testExpense._id}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Not authorized');

      // Verify expense still exists
      const stillExists = await Expense.findById(testExpense._id);
      expect(stillExists).toBeTruthy();
    });
  });

  describe('GET /api/v1/expenses/routes', () => {
    beforeEach(async () => {
      await Expense.create([
        {
          user: testUser._id,
          category: testCategory._id,
          startingPoint: 'Home',
          destinationPoint: 'Office',
          distance: 10,
          costPerKm: 2.5,
          totalCost: 25,
          journeyDate: new Date('2024-01-15'),
          routeData: {
            coordinates: [[0, 0], [1, 1]],
            duration: 30
          }
        },
        {
          user: testUser._id,
          category: testCategory._id,
          startingPoint: 'Office',
          destinationPoint: 'Client',
          distance: 20,
          costPerKm: 3.0,
          totalCost: 60,
          journeyDate: new Date('2024-01-20'),
          routeData: {
            coordinates: [[1, 1], [2, 2]],
            duration: 45
          }
        }
      ]);
    });

    test('should get expenses with route data', async () => {
      const response = await request(app)
        .get('/api/v1/expenses/routes')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.data[0]).toHaveProperty('routeData');
      expect(response.body.data[0].routeData).toHaveProperty('coordinates');
      expect(response.body.data[0].routeData).toHaveProperty('duration');
    });

    test('should not get routes without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/expenses/routes')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Not authorized');
    });
  });

  describe('POST /api/v1/expenses/enhance-notes', () => {
    test('should preview enhanced notes', async () => {
      const notesData = {
        originalNotes: 'Meeting with client',
        expenseData: {
          startingPoint: 'Home',
          destinationPoint: 'Client Office',
          distance: 15,
          totalCost: 45
        }
      };

      const response = await request(app)
        .post('/api/v1/expenses/enhance-notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(notesData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('enhancedNotes');
      expect(typeof response.body.data.enhancedNotes).toBe('string');
    });

    test('should not enhance notes without authentication', async () => {
      const notesData = {
        originalNotes: 'Meeting with client',
        expenseData: {
          startingPoint: 'Home',
          destinationPoint: 'Client Office'
        }
      };

      const response = await request(app)
        .post('/api/v1/expenses/enhance-notes')
        .send(notesData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Not authorized');
    });
  });

  afterAll(async () => {
    await disconnectTestDB();
  });
});