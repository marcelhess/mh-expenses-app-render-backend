import Category from '../../src/models/Category.js';
import Expense from '../../src/models/Expense.js';
import { createTestUser } from '../utils/testHelpers.js';

describe('Category Model', () => {
  let testUser;

  beforeEach(async () => {
    testUser = await createTestUser();
  });

  describe('Category Schema Validation', () => {
    test('should create a valid category', async () => {
      const categoryData = {
        name: 'Transportation',
        description: 'Travel and transportation expenses'
      };

      const category = new Category(categoryData);
      const savedCategory = await category.save();

      expect(savedCategory._id).toBeDefined();
      expect(savedCategory.name).toBe(categoryData.name);
      expect(savedCategory.description).toBe(categoryData.description);
      expect(savedCategory.isActive).toBe(true); // default value
      expect(savedCategory.currentUsage.monthly.amount).toBe(0); // default value
      expect(savedCategory.currentUsage.quarterly.amount).toBe(0); // default value
      expect(savedCategory.currentUsage.yearly.amount).toBe(0); // default value
      expect(savedCategory.createdAt).toBeDefined();
      expect(savedCategory.updatedAt).toBeDefined();
    });

    test('should require name field', async () => {
      const categoryData = {
        description: 'Test category description'
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Please add a category name');
    });

    test('should enforce unique name constraint', async () => {
      const categoryData1 = {
        name: 'Transportation',
        description: 'First transportation category'
      };

      const categoryData2 = {
        name: 'Transportation', // same name
        description: 'Second transportation category'
      };

      await Category.create(categoryData1);
      
      await expect(Category.create(categoryData2)).rejects.toThrow();
    });

    test('should enforce maximum name length', async () => {
      const categoryData = {
        name: 'a'.repeat(51), // 51 characters
        description: 'Test category description'
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Name cannot be more than 50 characters');
    });

    test('should enforce maximum description length', async () => {
      const categoryData = {
        name: 'Transportation',
        description: 'a'.repeat(501) // 501 characters
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Description cannot be more than 500 characters');
    });

    test('should trim name field', async () => {
      const categoryData = {
        name: '  Transportation  ',
        description: 'Test category description'
      };

      const category = await Category.create(categoryData);
      expect(category.name).toBe('Transportation');
    });
  });

  describe('Budget Limits', () => {
    test('should create category with budget limits', async () => {
      const budgetLimits = [
        {
          amount: 1000,
          period: 'monthly',
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31'),
          notificationThreshold: 80
        },
        {
          amount: 3000,
          period: 'quarterly',
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-03-31'),
          notificationThreshold: 75
        }
      ];

      const categoryData = {
        name: 'Transportation',
        description: 'Travel expenses',
        budgetLimits: budgetLimits
      };

      const category = await Category.create(categoryData);
      
      expect(category.budgetLimits).toHaveLength(2);
      expect(category.budgetLimits[0].amount).toBe(1000);
      expect(category.budgetLimits[0].period).toBe('monthly');
      expect(category.budgetLimits[0].notificationThreshold).toBe(80);
      expect(category.budgetLimits[1].amount).toBe(3000);
      expect(category.budgetLimits[1].period).toBe('quarterly');
      expect(category.budgetLimits[1].notificationThreshold).toBe(75);
    });

    test('should require budget amount', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          period: 'monthly',
          startDate: new Date('2024-01-01')
        }]
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Please add a budget amount');
    });

    test('should require budget period', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: 1000,
          startDate: new Date('2024-01-01')
        }]
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Please specify the budget period');
    });

    test('should require budget start date', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: 1000,
          period: 'monthly'
        }]
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Please add a start date for the budget period');
    });

    test('should validate budget period enum values', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: 1000,
          period: 'invalid_period',
          startDate: new Date('2024-01-01')
        }]
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow();
    });

    test('should validate notification threshold range', async () => {
      const categoryData1 = {
        name: 'Transportation1',
        budgetLimits: [{
          amount: 1000,
          period: 'monthly',
          startDate: new Date('2024-01-01'),
          notificationThreshold: 0 // below minimum
        }]
      };

      const categoryData2 = {
        name: 'Transportation2',
        budgetLimits: [{
          amount: 1000,
          period: 'monthly',
          startDate: new Date('2024-01-01'),
          notificationThreshold: 101 // above maximum
        }]
      };

      await expect(Category.create(categoryData1)).rejects.toThrow('Threshold must be at least 1%');
      await expect(Category.create(categoryData2)).rejects.toThrow('Threshold cannot exceed 100%');
    });

    test('should set default notification threshold', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: 1000,
          period: 'monthly',
          startDate: new Date('2024-01-01')
        }]
      };

      const category = await Category.create(categoryData);
      expect(category.budgetLimits[0].notificationThreshold).toBe(80);
    });

    test('should set default isActive for budget limits', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: 1000,
          period: 'monthly',
          startDate: new Date('2024-01-01')
        }]
      };

      const category = await Category.create(categoryData);
      expect(category.budgetLimits[0].isActive).toBe(true);
    });

    test('should validate negative budget amount', async () => {
      const categoryData = {
        name: 'Transportation',
        budgetLimits: [{
          amount: -100,
          period: 'monthly',
          startDate: new Date('2024-01-01')
        }]
      };

      const category = new Category(categoryData);
      
      await expect(category.save()).rejects.toThrow('Budget amount cannot be negative');
    });
  });

  describe('Current Usage Tracking', () => {
    test('should initialize current usage with default values', async () => {
      const categoryData = {
        name: 'Transportation',
        description: 'Travel expenses'
      };

      const category = await Category.create(categoryData);
      
      expect(category.currentUsage.monthly.amount).toBe(0);
      expect(category.currentUsage.quarterly.amount).toBe(0);
      expect(category.currentUsage.yearly.amount).toBe(0);
    });

    test('should update current usage amounts', async () => {
      const categoryData = {
        name: 'Transportation',
        currentUsage: {
          monthly: {
            amount: 500,
            lastUpdated: new Date()
          },
          quarterly: {
            amount: 1200,
            lastUpdated: new Date()
          },
          yearly: {
            amount: 4500,
            lastUpdated: new Date()
          }
        }
      };

      const category = await Category.create(categoryData);
      
      expect(category.currentUsage.monthly.amount).toBe(500);
      expect(category.currentUsage.quarterly.amount).toBe(1200);
      expect(category.currentUsage.yearly.amount).toBe(4500);
    });
  });

  describe('Category Status', () => {
    test('should create active category by default', async () => {
      const categoryData = {
        name: 'Transportation'
      };

      const category = await Category.create(categoryData);
      expect(category.isActive).toBe(true);
    });

    test('should allow creating inactive category', async () => {
      const categoryData = {
        name: 'Transportation',
        isActive: false
      };

      const category = await Category.create(categoryData);
      expect(category.isActive).toBe(false);
    });
  });

  describe('Static Methods', () => {
    describe('calculateBudgetUsage', () => {
      test('should calculate budget usage for category with expenses', async () => {
        // Create category
        const category = await Category.create({
          name: 'Transportation'
        });

        // Create expenses for the category
        const startDate = new Date('2024-01-01');
        const endDate = new Date('2024-01-31');
        
        await Expense.create({
          user: testUser._id,
          category: category._id,
          startingPoint: 'Home',
          destinationPoint: 'Office',
          distance: 10,
          costPerKm: 2.5,
          totalCost: 25,
          journeyDate: new Date('2024-01-15')
        });

        await Expense.create({
          user: testUser._id,
          category: category._id,
          startingPoint: 'Office',
          destinationPoint: 'Client',
          distance: 20,
          costPerKm: 3.0,
          totalCost: 60,
          journeyDate: new Date('2024-01-20')
        });

        const totalUsage = await Category.calculateBudgetUsage(
          category._id,
          startDate,
          endDate
        );

        expect(totalUsage).toBe(85); // 25 + 60
      });

      test('should return 0 for category with no expenses', async () => {
        const category = await Category.create({
          name: 'Transportation'
        });

        const startDate = new Date('2024-01-01');
        const endDate = new Date('2024-01-31');

        const totalUsage = await Category.calculateBudgetUsage(
          category._id,
          startDate,
          endDate
        );

        expect(totalUsage).toBe(0);
      });

      test('should only include expenses within date range', async () => {
        const category = await Category.create({
          name: 'Transportation'
        });

        const startDate = new Date('2024-01-01');
        const endDate = new Date('2024-01-31');

        // Expense within range
        await Expense.create({
          user: testUser._id,
          category: category._id,
          startingPoint: 'Home',
          destinationPoint: 'Office',
          distance: 10,
          costPerKm: 2.5,
          totalCost: 25,
          journeyDate: new Date('2024-01-15')
        });

        // Expense outside range
        await Expense.create({
          user: testUser._id,
          category: category._id,
          startingPoint: 'Office',
          destinationPoint: 'Client',
          distance: 20,
          costPerKm: 3.0,
          totalCost: 60,
          journeyDate: new Date('2024-02-15') // Outside range
        });

        const totalUsage = await Category.calculateBudgetUsage(
          category._id,
          startDate,
          endDate
        );

        expect(totalUsage).toBe(25); // Only the expense within range
      });
    });
  });

  describe('Category Queries', () => {
    test('should find active categories', async () => {
      await Category.create({
        name: 'Active Category',
        isActive: true
      });

      await Category.create({
        name: 'Inactive Category',
        isActive: false
      });

      const activeCategories = await Category.find({ isActive: true });
      expect(activeCategories).toHaveLength(1);
      expect(activeCategories[0].name).toBe('Active Category');
    });

    test('should find categories by name', async () => {
      const categoryName = 'Transportation';
      await Category.create({
        name: categoryName,
        description: 'Travel expenses'
      });

      const foundCategory = await Category.findOne({ name: categoryName });
      expect(foundCategory).toBeDefined();
      expect(foundCategory.name).toBe(categoryName);
    });
  });
});