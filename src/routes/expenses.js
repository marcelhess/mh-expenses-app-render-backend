import express from "express";
import {
  getExpenses,
  getExpenseById,
  createExpense,
  updateExpense,
  deleteExpense,
  previewEnhancedNotes,
  getExpensesWithRoutes,
} from "../controllers/expense.controller.js";

import { protect } from "../middleware/auth.js";
import validate from "../middleware/validate.js";
import {
  createExpenseValidation,
  updateExpenseValidation,
} from "../validations/expense.js";
import { modifyDataLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

/**
 * @swagger
 * /api/v1/expenses:
 *   get:
 *     summary: Get all expenses
 *     description: Retrieve a paginated list of expenses for the authenticated user with filtering and sorting options
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 10
 *         description: Number of expenses per page
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter expenses from this date (YYYY-MM-DD)
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter expenses until this date (YYYY-MM-DD)
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *           enum: [journeyDate, -journeyDate, totalCost, -totalCost, createdAt, -createdAt]
 *           default: -journeyDate
 *         description: Sort field and order (prefix with - for descending)
 *     responses:
 *       200:
 *         description: Expenses retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 count:
 *                   type: integer
 *                   description: Number of expenses returned
 *                   example: 10
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Expense'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *   post:
 *     summary: Create a new expense
 *     description: Create a new expense record with journey details and automatic cost calculation
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateExpenseRequest'
 *     responses:
 *       201:
 *         description: Expense created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Expense'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 */

/**
 * @swagger
 * /api/v1/expenses/{id}:
 *   get:
 *     summary: Get expense by ID
 *     description: Retrieve a specific expense by its ID
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Expense ID
 *         example: "60d5ecb74b24a1234567890a"
 *     responses:
 *       200:
 *         description: Expense retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Expense'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *   put:
 *     summary: Update expense
 *     description: Update an existing expense record
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Expense ID
 *         example: "60d5ecb74b24a1234567890a"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateExpenseRequest'
 *     responses:
 *       200:
 *         description: Expense updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Expense'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *   delete:
 *     summary: Delete expense
 *     description: Delete an existing expense record
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Expense ID
 *         example: "60d5ecb74b24a1234567890a"
 *     responses:
 *       200:
 *         description: Expense deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Expense deleted successfully"
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 */

/**
 * @swagger
 * /api/v1/expenses/enhance-notes:
 *   post:
 *     summary: Preview enhanced notes
 *     description: Generate AI-enhanced notes for an expense based on journey details
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - startingPoint
 *               - destinationPoint
 *               - journeyDate
 *             properties:
 *               startingPoint:
 *                 type: string
 *                 description: Starting location of the journey
 *                 example: "Downtown Office"
 *               destinationPoint:
 *                 type: string
 *                 description: Destination location of the journey
 *                 example: "Client Meeting - Uptown"
 *               journeyDate:
 *                 type: string
 *                 format: date-time
 *                 description: Date and time of the journey
 *                 example: "2024-01-15T09:00:00Z"
 *               notes:
 *                 type: string
 *                 description: Additional notes about the journey
 *                 example: "Important client presentation"
 *     responses:
 *       200:
 *         description: Enhanced notes generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     enhancedNotes:
 *                       type: string
 *                       description: AI-generated enhanced notes
 *                       example: "Business trip from Downtown Office to Client Meeting - Uptown on January 15, 2024. Purpose: Important client presentation. Journey undertaken for business development and client relationship management."
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 */

/**
 * @swagger
 * /api/v1/expenses/routes:
 *   get:
 *     summary: Get expenses with route data
 *     description: Retrieve expenses with geographical route information for map visualization
 *     tags: [Expenses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter expenses from this date (YYYY-MM-DD)
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter expenses until this date (YYYY-MM-DD)
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *     responses:
 *       200:
 *         description: Expenses with route data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 count:
 *                   type: integer
 *                   description: Number of expenses returned
 *                   example: 25
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/ExpenseWithRoute'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 */

// All routes require authentication
router.use(protect);

// Route for previewing enhanced notes
router.post("/enhance-notes", previewEnhancedNotes);

// Route for getting expenses with route data for visualization
router.get("/routes", getExpensesWithRoutes);

router
  .route("/")
  .get(getExpenses)
  .post(modifyDataLimiter, validate(createExpenseValidation), createExpense);

router
  .route("/:id")
  .get(getExpenseById)
  .put(modifyDataLimiter, validate(updateExpenseValidation), updateExpense)
  .delete(modifyDataLimiter, deleteExpense);

export default router;
