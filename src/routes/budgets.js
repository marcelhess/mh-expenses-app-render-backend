/**
 * @swagger
 * tags:
 *   name: Budgets
 *   description: Budget management endpoints
 */

/**
 * @swagger
 * /api/v1/budgets/summary:
 *   get:
 *     summary: Get budget summary
 *     description: Retrieve budget summary with spending overview
 *     tags: [Budgets]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: ["monthly", "quarterly", "yearly"]
 *         description: Filter by budget period
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *     responses:
 *       200:
 *         description: Budget summary retrieved successfully
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
 *                     totalBudget:
 *                       type: number
 *                       description: Total budget amount
 *                       example: 10000.00
 *                     totalSpent:
 *                       type: number
 *                       description: Total amount spent
 *                       example: 3500.75
 *                     totalRemaining:
 *                       type: number
 *                       description: Total remaining budget
 *                       example: 6499.25
 *                     budgetUtilization:
 *                       type: number
 *                       description: Budget utilization percentage
 *                       example: 35.01
 *                     budgets:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Budget'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */

/**
 * @swagger
 * /api/v1/budgets:
 *   get:
 *     summary: Get all budgets
 *     description: Retrieve all budgets for the authenticated user
 *     tags: [Budgets]
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
 *         description: Number of budgets per page
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: ["monthly", "quarterly", "yearly"]
 *         description: Filter by budget period
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: ["active", "expired", "upcoming"]
 *         description: Filter by budget status
 *     responses:
 *       200:
 *         description: Budgets retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Budget'
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *   post:
 *     summary: Create a new budget
 *     description: Create a new budget for expense tracking
 *     tags: [Budgets]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - amount
 *               - period
 *               - startDate
 *               - endDate
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 100
 *                 description: Budget name
 *                 example: "Q1 2024 Travel Budget"
 *               description:
 *                 type: string
 *                 maxLength: 500
 *                 description: Budget description
 *                 example: "Quarterly budget for business travel expenses"
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *                 description: Budget amount
 *                 example: 5000.00
 *               period:
 *                 type: string
 *                 enum: ["monthly", "quarterly", "yearly"]
 *                 description: Budget period
 *                 example: "quarterly"
 *               startDate:
 *                 type: string
 *                 format: date
 *                 description: Budget start date
 *                 example: "2024-01-01"
 *               endDate:
 *                 type: string
 *                 format: date
 *                 description: Budget end date
 *                 example: "2024-03-31"
 *               categories:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Associated category IDs
 *                 example: ["60d5ecb74b24a1234567890b"]
 *     responses:
 *       201:
 *         description: Budget created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Budget'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Budget name already exists or date conflict
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */

/**
 * @swagger
 * /api/v1/budgets/{id}:
 *   get:
 *     summary: Get budget by ID
 *     description: Retrieve a specific budget by its ID with detailed spending information
 *     tags: [Budgets]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Budget ID
 *     responses:
 *       200:
 *         description: Budget retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   allOf:
 *                     - $ref: '#/components/schemas/Budget'
 *                     - type: object
 *                       properties:
 *                         expenses:
 *                           type: array
 *                           items:
 *                             $ref: '#/components/schemas/Expense'
 *                         spendingByCategory:
 *                           type: array
 *                           items:
 *                             type: object
 *                             properties:
 *                               category:
 *                                 $ref: '#/components/schemas/Category'
 *                               spent:
 *                                 type: number
 *                                 example: 750.25
 *                               percentage:
 *                                 type: number
 *                                 example: 15.01
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Budget not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *   put:
 *     summary: Update budget
 *     description: Update an existing budget
 *     tags: [Budgets]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Budget ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 100
 *                 description: Budget name
 *                 example: "Q1 2024 Travel Budget"
 *               description:
 *                 type: string
 *                 maxLength: 500
 *                 description: Budget description
 *                 example: "Quarterly budget for business travel expenses"
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *                 description: Budget amount
 *                 example: 5000.00
 *               period:
 *                 type: string
 *                 enum: ["monthly", "quarterly", "yearly"]
 *                 description: Budget period
 *                 example: "quarterly"
 *               startDate:
 *                 type: string
 *                 format: date
 *                 description: Budget start date
 *                 example: "2024-01-01"
 *               endDate:
 *                 type: string
 *                 format: date
 *                 description: Budget end date
 *                 example: "2024-03-31"
 *               categories:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Associated category IDs
 *                 example: ["60d5ecb74b24a1234567890b"]
 *     responses:
 *       200:
 *         description: Budget updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Budget'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Budget not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Budget name already exists or date conflict
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *   delete:
 *     summary: Delete budget
 *     description: Delete a budget (this will not delete associated expenses)
 *     tags: [Budgets]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Budget ID
 *     responses:
 *       200:
 *         description: Budget deleted successfully
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
 *                   example: "Budget deleted successfully"
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Budget not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */

import express from "express";
import { protect } from "../middleware/auth.js";
import {
  getBudgets,
  getBudget,
  createBudget,
  updateBudget,
  deleteBudget,
  getBudgetSummary,
} from "../controllers/budgets.js";

const router = express.Router();

// All routes need authentication
router.use(protect);

// Budget summary route
router.get("/summary", getBudgetSummary);

// Standard RESTful routes
router.route("/").get(getBudgets).post(createBudget);

router.route("/:id").get(getBudget).put(updateBudget).delete(deleteBudget);

export default router;
