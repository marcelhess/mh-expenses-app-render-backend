import Budget from '../../src/models/Budget.js';
import Category from '../../src/models/Category.js';
import { createTestUser } from '../utils/testHelpers.js';

describe('Budget Model', () => {
  let testUser;
  let testCategory;

  beforeEach(async () => {
    testUser = await createTestUser();
    testCategory = await Category.create({
      name: 'Transportation',
      description: 'Travel expenses'
    });
  });

  describe('Budget Schema Validation', () => {
    test('should create a valid budget', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1000,
        maxDistance: 500,
        notes: 'Monthly transportation budget'
      };

      const budget = new Budget(budgetData);
      const savedBudget = await budget.save();

      expect(savedBudget._id).toBeDefined();
      expect(savedBudget.user.toString()).toBe(testUser._id.toString());
      expect(savedBudget.category.toString()).toBe(testCategory._id.toString());
      expect(savedBudget.year).toBe(2024);
      expect(savedBudget.month).toBe(1);
      expect(savedBudget.amount).toBe(1000);
      expect(savedBudget.maxDistance).toBe(500);
      expect(savedBudget.notes).toBe('Monthly transportation budget');
      expect(savedBudget.isActive).toBe(true); // default value
      expect(savedBudget.isGlobal).toBe(false); // default value
      expect(savedBudget.warningThreshold).toBe(70); // default value
      expect(savedBudget.criticalThreshold).toBe(90); // default value
      expect(savedBudget.createdAt).toBeDefined();
      expect(savedBudget.updatedAt).toBeDefined();
    });

    test('should require user field', async () => {
      const budgetData = {
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = new Budget(budgetData);
      
      await expect(budget.save()).rejects.toThrow('Path `user` is required');
    });

    test('should require category field', async () => {
      const budgetData = {
        user: testUser._id,
        year: 2024,
        amount: 1000
      };

      const budget = new Budget(budgetData);
      
      await expect(budget.save()).rejects.toThrow('Path `category` is required');
    });

    test('should require year field', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        amount: 1000
      };

      const budget = new Budget(budgetData);
      
      await expect(budget.save()).rejects.toThrow('Please add a year');
    });

    test('should require amount field', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024
      };

      const budget = new Budget(budgetData);
      
      await expect(budget.save()).rejects.toThrow('Please add a budget amount');
    });

    test('should validate year range', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 1999, // below minimum
        amount: 1000
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2101, // above maximum
        amount: 1000
      };

      await expect(Budget.create(budgetData1)).rejects.toThrow('Year must be 2000 or later');
      await expect(Budget.create(budgetData2)).rejects.toThrow('Year must be 2100 or earlier');
    });

    test('should validate month range', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: -1, // below minimum
        amount: 1000
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 13, // above maximum
        amount: 1000
      };

      await expect(Budget.create(budgetData1)).rejects.toThrow('Month must be between 0 and 12');
      await expect(Budget.create(budgetData2)).rejects.toThrow('Month must be between 0 and 12');
    });

    test('should validate positive budget amount', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: -100 // negative amount
      };

      const budget = new Budget(budgetData);
      
      await expect(budget.save()).rejects.toThrow('Budget amount must be positive');
    });

    test('should validate warning threshold range', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        warningThreshold: -1 // below minimum
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        warningThreshold: 101 // above maximum
      };

      await expect(Budget.create(budgetData1)).rejects.toThrow('Threshold must be between 0 and 100');
      await expect(Budget.create(budgetData2)).rejects.toThrow('Threshold must be between 0 and 100');
    });

    test('should validate critical threshold range', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        criticalThreshold: -1 // below minimum
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        criticalThreshold: 101 // above maximum
      };

      await expect(Budget.create(budgetData1)).rejects.toThrow('Threshold must be between 0 and 100');
      await expect(Budget.create(budgetData2)).rejects.toThrow('Threshold must be between 0 and 100');
    });

    test('should set default month to 0 for annual budget', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.month).toBe(0);
    });

    test('should set default maxDistance to 0', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.maxDistance).toBe(0);
    });

    test('should trim notes field', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        notes: '  Budget notes with spaces  '
      };

      const budget = await Budget.create(budgetData);
      expect(budget.notes).toBe('Budget notes with spaces');
    });
  });

  describe('Budget Types', () => {
    test('should create annual budget (month = 0)', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 0,
        amount: 12000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.month).toBe(0);
    });

    test('should create monthly budget (month = 1-12)', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 6,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.month).toBe(6);
    });

    test('should create global budget', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        isGlobal: true
      };

      const budget = await Budget.create(budgetData);
      expect(budget.isGlobal).toBe(true);
    });

    test('should create personal budget by default', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.isGlobal).toBe(false);
    });
  });

  describe('Budget Status', () => {
    test('should create active budget by default', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.isActive).toBe(true);
    });

    test('should allow creating inactive budget', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        isActive: false
      };

      const budget = await Budget.create(budgetData);
      expect(budget.isActive).toBe(false);
    });
  });

  describe('Virtual Properties', () => {
    test('should calculate remaining amount when no actual expenses', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.remainingAmount).toBe(1000);
    });

    test('should calculate remaining amount with actual expenses', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        actualExpenses: 300
      };

      const budget = await Budget.create(budgetData);
      expect(budget.remainingAmount).toBe(700);
    });

    test('should calculate usage percentage when no actual expenses', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      const budget = await Budget.create(budgetData);
      expect(budget.usagePercentage).toBe(0);
    });

    test('should calculate usage percentage with actual expenses', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        actualExpenses: 250
      };

      const budget = await Budget.create(budgetData);
      expect(budget.usagePercentage).toBe(25); // 250/1000 * 100 = 25%
    });

    test('should round usage percentage to nearest integer', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        actualExpenses: 333 // 33.3%
      };

      const budget = await Budget.create(budgetData);
      expect(budget.usagePercentage).toBe(33); // Rounded down
    });
  });

  describe('Compound Index and Uniqueness', () => {
    test('should enforce unique budget per user, year, month, category for active budgets', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1000,
        isActive: true
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1, // same combination
        amount: 1500,
        isActive: true
      };

      await Budget.create(budgetData1);
      
      await expect(Budget.create(budgetData2)).rejects.toThrow();
    });

    test('should allow multiple inactive budgets with same combination', async () => {
      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1000,
        isActive: false
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1, // same combination
        amount: 1500,
        isActive: false
      };

      const budget1 = await Budget.create(budgetData1);
      const budget2 = await Budget.create(budgetData2);

      expect(budget1._id).toBeDefined();
      expect(budget2._id).toBeDefined();
      expect(budget1._id.toString()).not.toBe(budget2._id.toString());
    });

    test('should allow same combination for different users', async () => {
      const testUser2 = await createTestUser({
        name: 'Test User 2',
        email: 'testuser2@example.com',
        phone: '+233987654321'
      });

      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1000,
        isActive: true
      };

      const budgetData2 = {
        user: testUser2._id, // different user
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1500,
        isActive: true
      };

      const budget1 = await Budget.create(budgetData1);
      const budget2 = await Budget.create(budgetData2);

      expect(budget1._id).toBeDefined();
      expect(budget2._id).toBeDefined();
    });

    test('should allow same combination for different categories', async () => {
      const testCategory2 = await Category.create({
        name: 'Food',
        description: 'Food and dining expenses'
      });

      const budgetData1 = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        month: 1,
        amount: 1000,
        isActive: true
      };

      const budgetData2 = {
        user: testUser._id,
        category: testCategory2._id, // different category
        year: 2024,
        month: 1,
        amount: 1500,
        isActive: true
      };

      const budget1 = await Budget.create(budgetData1);
      const budget2 = await Budget.create(budgetData2);

      expect(budget1._id).toBeDefined();
      expect(budget2._id).toBeDefined();
    });
  });

  describe('Budget Queries', () => {
    test('should find budgets by user', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      await Budget.create(budgetData);

      const userBudgets = await Budget.find({ user: testUser._id });
      expect(userBudgets).toHaveLength(1);
      expect(userBudgets[0].user.toString()).toBe(testUser._id.toString());
    });

    test('should find budgets by year', async () => {
      const budgetData = {
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000
      };

      await Budget.create(budgetData);

      const yearBudgets = await Budget.find({ year: 2024 });
      expect(yearBudgets).toHaveLength(1);
      expect(yearBudgets[0].year).toBe(2024);
    });

    test('should find active budgets', async () => {
      await Budget.create({
        user: testUser._id,
        category: testCategory._id,
        year: 2024,
        amount: 1000,
        isActive: true
      });

      await Budget.create({
        user: testUser._id,
        category: testCategory._id,
        year: 2023,
        amount: 800,
        isActive: false
      });

      const activeBudgets = await Budget.find({ isActive: true });
      expect(activeBudgets).toHaveLength(1);
      expect(activeBudgets[0].isActive).toBe(true);
    });
  });
});