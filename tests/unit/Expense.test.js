import Expense from '../../src/models/Expense.js';
import User from '../../src/models/User.js';
import Category from '../../src/models/Category.js';
import { createTestUser, createTestCategory } from '../utils/testHelpers.js';

describe('Expense Model', () => {
  let testUser;
  let testCategory;

  beforeEach(async () => {
    testUser = await createTestUser();
    testCategory = await createTestCategory(testUser._id);
  });

  describe('Expense Schema Validation', () => {
    test('should create a valid expense', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        journeyDate: new Date()
      };

      const expense = new Expense(expenseData);
      const savedExpense = await expense.save();

      expect(savedExpense._id).toBeDefined();
      expect(savedExpense.user.toString()).toBe(testUser._id.toString());
      expect(savedExpense.category.toString()).toBe(testCategory._id.toString());
      expect(savedExpense.startingPoint).toBe(expenseData.startingPoint);
      expect(savedExpense.destinationPoint).toBe(expenseData.destinationPoint);
      expect(savedExpense.distance).toBe(expenseData.distance);
      expect(savedExpense.costPerKm).toBe(expenseData.costPerKm);
      expect(savedExpense.status).toBe('pending'); // default status
      expect(savedExpense.isCalculatedDistance).toBe(false); // default value
      expect(savedExpense.createdAt).toBeDefined();
      expect(savedExpense.updatedAt).toBeDefined();
    });

    test('should require user field', async () => {
      const expenseData = {
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow();
    });

    test('should require category field', async () => {
      const expenseData = {
        user: testUser._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow();
    });

    test('should require starting point', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow('Please add a starting point');
    });

    test('should require destination point', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow('Please add a destination point');
    });

    test('should require distance', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow('Please add the distance in kilometers');
    });

    test('should require cost per km', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow('Please add the cost per kilometer');
    });

    test('should require total cost', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow('Please add the total cost');
    });

    test('should validate status enum values', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        status: 'invalid_status'
      };

      const expense = new Expense(expenseData);
      
      await expect(expense.save()).rejects.toThrow();
    });

    test('should set default journey date', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = new Expense(expenseData);
      const savedExpense = await expense.save();
      
      expect(savedExpense.journeyDate).toBeDefined();
      expect(savedExpense.journeyDate).toBeInstanceOf(Date);
    });
  });

  describe('Total Cost Calculation', () => {
    test('should calculate total cost automatically', async () => {
      const distance = 15;
      const costPerKm = 3.0;
      const expectedTotalCost = distance * costPerKm;

      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: distance,
        costPerKm: costPerKm,
        totalCost: 0 // This should be overridden by pre-save middleware
      };

      const expense = new Expense(expenseData);
      const savedExpense = await expense.save();
      
      expect(savedExpense.totalCost).toBe(expectedTotalCost);
    });

    test('should recalculate total cost when distance changes', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = await Expense.create(expenseData);
      
      // Update distance
      expense.distance = 20;
      const updatedExpense = await expense.save();
      
      expect(updatedExpense.totalCost).toBe(50); // 20 * 2.5
    });

    test('should recalculate total cost when cost per km changes', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = await Expense.create(expenseData);
      
      // Update cost per km
      expense.costPerKm = 3.0;
      const updatedExpense = await expense.save();
      
      expect(updatedExpense.totalCost).toBe(30); // 10 * 3.0
    });
  });

  describe('Expense Status Management', () => {
    test('should create expense with pending status by default', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = await Expense.create(expenseData);
      expect(expense.status).toBe('pending');
    });

    test('should allow approved status', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        status: 'approved'
      };

      const expense = await Expense.create(expenseData);
      expect(expense.status).toBe('approved');
    });

    test('should allow rejected status', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        status: 'rejected'
      };

      const expense = await Expense.create(expenseData);
      expect(expense.status).toBe('rejected');
    });
  });

  describe('Waypoints and Route Data', () => {
    test('should store waypoints correctly', async () => {
      const waypoints = [
        {
          placeId: 'place1',
          description: 'Gas Station',
          formattedAddress: '123 Main St'
        },
        {
          placeId: 'place2',
          description: 'Restaurant',
          formattedAddress: '456 Oak Ave'
        }
      ];

      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        waypoints: waypoints
      };

      const expense = await Expense.create(expenseData);
      
      expect(expense.waypoints).toHaveLength(2);
      expect(expense.waypoints[0].placeId).toBe('place1');
      expect(expense.waypoints[0].description).toBe('Gas Station');
      expect(expense.waypoints[1].placeId).toBe('place2');
      expect(expense.waypoints[1].description).toBe('Restaurant');
    });

    test('should store route snapshot', async () => {
      const routeSnapshot = {
        polyline: 'encoded_polyline_string',
        bounds: {
          northeast: { lat: 40.7128, lng: -74.0060 },
          southwest: { lat: 40.7000, lng: -74.0200 }
        }
      };

      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        routeSnapshot: routeSnapshot
      };

      const expense = await Expense.create(expenseData);
      
      expect(expense.routeSnapshot).toEqual(routeSnapshot);
    });
  });

  describe('Expense Relationships', () => {
    test('should populate user relationship', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = await Expense.create(expenseData);
      const populatedExpense = await Expense.findById(expense._id).populate('user');
      
      expect(populatedExpense.user.name).toBe(testUser.name);
      expect(populatedExpense.user.email).toBe(testUser.email);
    });

    test('should populate category relationship', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      const expense = await Expense.create(expenseData);
      const populatedExpense = await Expense.findById(expense._id).populate('category');
      
      expect(populatedExpense.category.name).toBe(testCategory.name);
    });
  });

  describe('Expense Queries', () => {
    test('should find expenses by user', async () => {
      const expenseData = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25
      };

      await Expense.create(expenseData);
      const userExpenses = await Expense.find({ user: testUser._id });
      
      expect(userExpenses).toHaveLength(1);
      expect(userExpenses[0].user.toString()).toBe(testUser._id.toString());
    });

    test('should find expenses by status', async () => {
      const expenseData1 = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Home',
        destinationPoint: 'Office',
        distance: 10,
        costPerKm: 2.5,
        totalCost: 25,
        status: 'pending'
      };

      const expenseData2 = {
        user: testUser._id,
        category: testCategory._id,
        startingPoint: 'Office',
        destinationPoint: 'Client',
        distance: 15,
        costPerKm: 2.5,
        totalCost: 37.5,
        status: 'approved'
      };

      await Expense.create(expenseData1);
      await Expense.create(expenseData2);
      
      const pendingExpenses = await Expense.find({ status: 'pending' });
      const approvedExpenses = await Expense.find({ status: 'approved' });
      
      expect(pendingExpenses).toHaveLength(1);
      expect(approvedExpenses).toHaveLength(1);
    });
  });
});