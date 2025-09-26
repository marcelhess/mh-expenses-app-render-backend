import request from 'supertest';
import app from '../../src/app.js';
import User from '../../src/models/User.js';
import Category from '../../src/models/Category.js';
import { connectTestDB, clearTestDB, disconnectTestDB } from '../setup/testDb.js';

describe('Category Endpoints', () => {
  let userToken;
  let adminToken;
  let userId;
  let adminId;

  beforeAll(async () => {
    await connectTestDB();
  });

  beforeEach(async () => {
    await clearTestDB();

    // Create test user
    const user = await User.create({
      name: 'Test User',
      email: 'user@example.com',
      password: 'password123',
      role: 'user'
    });
    userId = user._id;
    userToken = user.getSignedJwtToken();

    // Create test admin
    const admin = await User.create({
      name: 'Test Admin',
      email: 'admin@example.com',
      password: 'password123',
      role: 'admin'
    });
    adminId = admin._id;
    adminToken = admin.getSignedJwtToken();
  });

  afterAll(async () => {
    await disconnectTestDB();
  });

  describe('GET /api/v1/categories', () => {
    beforeEach(async () => {
      // Create test categories
      await Category.create([
        {
          name: 'Transportation',
          description: 'Travel and transport expenses',
          user: adminId,
          isActive: true
        },
        {
          name: 'Food',
          description: 'Food and dining expenses',
          user: adminId,
          isActive: true
        },
        {
          name: 'Inactive Category',
          description: 'This category is inactive',
          user: adminId,
          isActive: false
        }
      ]);
    });

    it('should get all active categories for authenticated user', async () => {
      const response = await request(app)
        .get('/api/v1/categories')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.data.every(cat => cat.isActive)).toBe(true);
    });

    it('should filter categories by active status', async () => {
      const response = await request(app)
        .get('/api/v1/categories?isActive=false')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].isActive).toBe(false);
    });

    it('should search categories by name', async () => {
      const response = await request(app)
        .get('/api/v1/categories?search=Transport')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].name).toBe('Transportation');
    });

    it('should paginate results', async () => {
      const response = await request(app)
        .get('/api/v1/categories?page=1&limit=1')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.pagination).toBeDefined();
      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(1);
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/v1/categories')
        .expect(401);
    });
  });

  describe('GET /api/v1/categories/summary', () => {
    beforeEach(async () => {
      await Category.create([
        {
          name: 'Transportation',
          description: 'Travel expenses',
          user: adminId,
          currentUsage: { monthly: 500, yearly: 6000 }
        },
        {
          name: 'Food',
          description: 'Food expenses',
          user: adminId,
          currentUsage: { monthly: 300, yearly: 3600 }
        }
      ]);
    });

    it('should get category summary', async () => {
      const response = await request(app)
        .get('/api/v1/categories/summary')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('totalCategories');
      expect(response.body.data).toHaveProperty('activeCategories');
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/v1/categories/summary')
        .expect(401);
    });
  });

  describe('GET /api/v1/categories/:id', () => {
    let categoryId;

    beforeEach(async () => {
      const category = await Category.create({
        name: 'Transportation',
        description: 'Travel and transport expenses',
        user: adminId
      });
      categoryId = category._id;
    });

    it('should get single category by ID', async () => {
      const response = await request(app)
        .get(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data._id).toBe(categoryId.toString());
      expect(response.body.data.name).toBe('Transportation');
    });

    it('should return 404 for non-existent category', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .get(`/api/v1/categories/${fakeId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(404);
    });

    it('should require authentication', async () => {
      await request(app)
        .get(`/api/v1/categories/${categoryId}`)
        .expect(401);
    });
  });

  describe('POST /api/v1/categories', () => {
    it('should create new category with admin role', async () => {
      const categoryData = {
        name: 'Entertainment',
        description: 'Entertainment and leisure expenses',
        budgetLimits: [
          {
            amount: 500,
            period: 'monthly',
            startDate: new Date(),
            endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          }
        ]
      };

      const response = await request(app)
        .post('/api/v1/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(categoryData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe('Entertainment');
      expect(response.body.data.user).toBe(adminId.toString());
      expect(response.body.data.budgetLimits).toHaveLength(1);

      // Verify in database
      const category = await Category.findById(response.body.data._id);
      expect(category).toBeTruthy();
      expect(category.name).toBe('Entertainment');
    });

    it('should not allow regular users to create categories', async () => {
      const categoryData = {
        name: 'Entertainment',
        description: 'Entertainment expenses'
      };

      await request(app)
        .post('/api/v1/categories')
        .set('Authorization', `Bearer ${userToken}`)
        .send(categoryData)
        .expect(403);
    });

    it('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/v1/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('required');
    });

    it('should validate unique category name', async () => {
      await Category.create({
        name: 'Transportation',
        description: 'Travel expenses',
        user: adminId
      });

      const categoryData = {
        name: 'Transportation',
        description: 'Another transport category'
      };

      const response = await request(app)
        .post('/api/v1/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(categoryData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should require authentication', async () => {
      await request(app)
        .post('/api/v1/categories')
        .send({ name: 'Test', description: 'Test' })
        .expect(401);
    });
  });

  describe('PUT /api/v1/categories/:id', () => {
    let categoryId;

    beforeEach(async () => {
      const category = await Category.create({
        name: 'Transportation',
        description: 'Travel expenses',
        user: adminId
      });
      categoryId = category._id;
    });

    it('should update category with admin role', async () => {
      const updateData = {
        name: 'Transport & Travel',
        description: 'Updated description for transport'
      };

      const response = await request(app)
        .put(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe('Transport & Travel');
      expect(response.body.data.description).toBe('Updated description for transport');

      // Verify in database
      const category = await Category.findById(categoryId);
      expect(category.name).toBe('Transport & Travel');
    });

    it('should not allow regular users to update categories', async () => {
      const updateData = {
        name: 'Updated Name'
      };

      await request(app)
        .put(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send(updateData)
        .expect(403);
    });

    it('should return 404 for non-existent category', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .put(`/api/v1/categories/${fakeId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ name: 'Updated' })
        .expect(404);
    });

    it('should validate updated data', async () => {
      const updateData = {
        name: '' // Empty name should fail validation
      };

      const response = await request(app)
        .put(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updateData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('DELETE /api/v1/categories/:id', () => {
    let categoryId;

    beforeEach(async () => {
      const category = await Category.create({
        name: 'Transportation',
        description: 'Travel expenses',
        user: adminId
      });
      categoryId = category._id;
    });

    it('should delete category with admin role', async () => {
      const response = await request(app)
        .delete(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify deletion in database
      const category = await Category.findById(categoryId);
      expect(category).toBeNull();
    });

    it('should not allow regular users to delete categories', async () => {
      await request(app)
        .delete(`/api/v1/categories/${categoryId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);

      // Verify category still exists
      const category = await Category.findById(categoryId);
      expect(category).toBeTruthy();
    });

    it('should return 404 for non-existent category', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      
      await request(app)
        .delete(`/api/v1/categories/${fakeId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });
  });

  describe('Budget Limit Management', () => {
    let categoryId;

    beforeEach(async () => {
      const category = await Category.create({
        name: 'Transportation',
        description: 'Travel expenses',
        user: adminId
      });
      categoryId = category._id;
    });

    describe('POST /api/v1/categories/:id/budget', () => {
      it('should add budget limit with admin role', async () => {
        const budgetData = {
          amount: 1000,
          period: 'monthly',
          startDate: new Date(),
          endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        };

        const response = await request(app)
          .post(`/api/v1/categories/${categoryId}/budget`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send(budgetData)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.budgetLimits).toHaveLength(1);
        expect(response.body.data.budgetLimits[0].amount).toBe(1000);
      });

      it('should not allow regular users to add budget limits', async () => {
        const budgetData = {
          amount: 1000,
          period: 'monthly'
        };

        await request(app)
          .post(`/api/v1/categories/${categoryId}/budget`)
          .set('Authorization', `Bearer ${userToken}`)
          .send(budgetData)
          .expect(403);
      });

      it('should validate budget limit data', async () => {
        const budgetData = {
          amount: -100, // Invalid negative amount
          period: 'monthly'
        };

        const response = await request(app)
          .post(`/api/v1/categories/${categoryId}/budget`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send(budgetData)
          .expect(400);

        expect(response.body.success).toBe(false);
      });
    });

    describe('GET /api/v1/categories/:id/budget/usage', () => {
      beforeEach(async () => {
        await Category.findByIdAndUpdate(categoryId, {
          currentUsage: {
            monthly: 500,
            quarterly: 1500,
            yearly: 6000
          }
        });
      });

      it('should get budget usage for category', async () => {
        const response = await request(app)
          .get(`/api/v1/categories/${categoryId}/budget/usage`)
          .set('Authorization', `Bearer ${userToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data).toHaveProperty('currentUsage');
        expect(response.body.data.currentUsage.monthly).toBe(500);
      });

      it('should require authentication', async () => {
        await request(app)
          .get(`/api/v1/categories/${categoryId}/budget/usage`)
          .expect(401);
      });
    });
  });

  describe('Category Usage Calculation', () => {
    let categoryId;

    beforeEach(async () => {
      const category = await Category.create({
        name: 'Transportation',
        description: 'Travel expenses',
        user: adminId,
        budgetLimits: [
          {
            amount: 1000,
            period: 'monthly',
            startDate: new Date(),
            endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          }
        ]
      });
      categoryId = category._id;
    });

    it('should update budget usage via internal API', async () => {
      const usageData = {
        period: 'monthly',
        amount: 250
      };

      const response = await request(app)
        .post(`/api/v1/categories/${categoryId}/budget/update-usage`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(usageData)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify usage was updated
      const category = await Category.findById(categoryId);
      expect(category.currentUsage.monthly).toBe(250);
    });
  });
});