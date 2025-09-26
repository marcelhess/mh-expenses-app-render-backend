/**
 * @swagger
 * tags:
 *   name: Analytics
 *   description: Analytics and reporting endpoints for expense data
 */

/**
 * @swagger
 * /api/v1/analytics/dashboard:
 *   get:
 *     summary: Get dashboard summary
 *     description: Retrieve comprehensive dashboard analytics including total expenses, budget utilization, and key metrics
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: ["week", "month", "quarter", "year"]
 *           default: "month"
 *         description: Time period for dashboard data
 *     responses:
 *       200:
 *         description: Dashboard summary retrieved successfully
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
 *                     totalExpenses:
 *                       type: number
 *                       description: Total expenses for the period
 *                       example: 15750.50
 *                     totalBudget:
 *                       type: number
 *                       description: Total budget for the period
 *                       example: 20000.00
 *                     budgetUtilization:
 *                       type: number
 *                       description: Budget utilization percentage
 *                       example: 78.75
 *                     expenseCount:
 *                       type: integer
 *                       description: Number of expenses in the period
 *                       example: 45
 *                     topCategories:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           category:
 *                             $ref: '#/components/schemas/Category'
 *                           amount:
 *                             type: number
 *                             example: 3250.75
 *                           percentage:
 *                             type: number
 *                             example: 20.64
 *                     recentExpenses:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Expense'
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
 * /api/v1/analytics/expenses/time-summary:
 *   get:
 *     summary: Get expenses by time period
 *     description: Retrieve expense summaries grouped by time periods (daily, weekly, monthly)
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: ["daily", "weekly", "monthly", "yearly"]
 *           default: "monthly"
 *         description: Time period grouping
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for analysis
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for analysis
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *     responses:
 *       200:
 *         description: Time period summary retrieved successfully
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
 *                     type: object
 *                     properties:
 *                       period:
 *                         type: string
 *                         description: Time period label
 *                         example: "2024-01"
 *                       totalAmount:
 *                         type: number
 *                         description: Total expenses for the period
 *                         example: 2450.75
 *                       expenseCount:
 *                         type: integer
 *                         description: Number of expenses in the period
 *                         example: 12
 *                       averageAmount:
 *                         type: number
 *                         description: Average expense amount
 *                         example: 204.23
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
 * /api/v1/analytics/expenses/period-detail:
 *   get:
 *     summary: Get detailed expenses for a specific period
 *     description: Retrieve detailed expense breakdown for a specific time period
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         required: true
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for the period
 *       - in: query
 *         name: endDate
 *         required: true
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for the period
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
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
 *           default: 20
 *         description: Number of expenses per page
 *     responses:
 *       200:
 *         description: Period detail retrieved successfully
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
 *                     summary:
 *                       type: object
 *                       properties:
 *                         totalAmount:
 *                           type: number
 *                           example: 5750.25
 *                         expenseCount:
 *                           type: integer
 *                           example: 28
 *                         averageAmount:
 *                           type: number
 *                           example: 205.37
 *                     expenses:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Expense'
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 *       400:
 *         description: Invalid date parameters
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
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
 * /api/v1/analytics/expenses/category-breakdown:
 *   get:
 *     summary: Get expenses breakdown by category
 *     description: Retrieve expense analysis grouped by categories with percentages and totals
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for analysis
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for analysis
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *         description: Number of top categories to return
 *     responses:
 *       200:
 *         description: Category breakdown retrieved successfully
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
 *                     totalAmount:
 *                       type: number
 *                       description: Total amount across all categories
 *                       example: 12500.75
 *                     categories:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           category:
 *                             $ref: '#/components/schemas/Category'
 *                           totalAmount:
 *                             type: number
 *                             description: Total amount for this category
 *                             example: 3250.50
 *                           expenseCount:
 *                             type: integer
 *                             description: Number of expenses in this category
 *                             example: 15
 *                           percentage:
 *                             type: number
 *                             description: Percentage of total expenses
 *                             example: 26.00
 *                           averageAmount:
 *                             type: number
 *                             description: Average expense amount for this category
 *                             example: 216.70
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
 * /api/v1/analytics/expenses/trends:
 *   get:
 *     summary: Get expense trends analysis
 *     description: Retrieve expense trends showing growth patterns and comparisons over time
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: ["monthly", "quarterly", "yearly"]
 *           default: "monthly"
 *         description: Trend analysis period
 *       - in: query
 *         name: months
 *         schema:
 *           type: integer
 *           minimum: 3
 *           maximum: 24
 *           default: 12
 *         description: Number of periods to analyze
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *     responses:
 *       200:
 *         description: Expense trends retrieved successfully
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
 *                     trends:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           period:
 *                             type: string
 *                             example: "2024-01"
 *                           amount:
 *                             type: number
 *                             example: 2450.75
 *                           growthRate:
 *                             type: number
 *                             description: Growth rate compared to previous period
 *                             example: 12.5
 *                           expenseCount:
 *                             type: integer
 *                             example: 18
 *                     summary:
 *                       type: object
 *                       properties:
 *                         averageGrowthRate:
 *                           type: number
 *                           description: Average growth rate across periods
 *                           example: 8.3
 *                         totalGrowth:
 *                           type: number
 *                           description: Total growth from first to last period
 *                           example: 45.2
 *                         highestPeriod:
 *                           type: object
 *                           properties:
 *                             period:
 *                               type: string
 *                               example: "2024-03"
 *                             amount:
 *                               type: number
 *                               example: 3250.90
 *                         lowestPeriod:
 *                           type: object
 *                           properties:
 *                             period:
 *                               type: string
 *                               example: "2024-01"
 *                             amount:
 *                               type: number
 *                               example: 1850.25
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
 * /api/v1/analytics/expenses/yearly-comparison:
 *   get:
 *     summary: Get yearly expense comparison
 *     description: Compare expenses across different years with detailed breakdown
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: years
 *         schema:
 *           type: array
 *           items:
 *             type: integer
 *         style: form
 *         explode: false
 *         description: Years to compare (comma-separated)
 *         example: "2023,2024"
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category ID
 *     responses:
 *       200:
 *         description: Yearly comparison retrieved successfully
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
 *                     comparison:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           year:
 *                             type: integer
 *                             example: 2024
 *                           totalAmount:
 *                             type: number
 *                             example: 45750.25
 *                           expenseCount:
 *                             type: integer
 *                             example: 234
 *                           averageMonthly:
 *                             type: number
 *                             example: 3812.52
 *                           monthlyBreakdown:
 *                             type: array
 *                             items:
 *                               type: object
 *                               properties:
 *                                 month:
 *                                   type: integer
 *                                   example: 1
 *                                 amount:
 *                                   type: number
 *                                   example: 3250.75
 *                                 expenseCount:
 *                                   type: integer
 *                                   example: 18
 *                     summary:
 *                       type: object
 *                       properties:
 *                         yearOverYearGrowth:
 *                           type: number
 *                           description: Growth rate between years
 *                           example: 15.3
 *                         bestPerformingYear:
 *                           type: object
 *                           properties:
 *                             year:
 *                               type: integer
 *                               example: 2023
 *                             amount:
 *                               type: number
 *                               example: 39750.50
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

import express from "express";
import { protect } from "../middleware/auth.js";
import {
  getExpensesByTimePeriod,
  getExpensesForPeriod,
  getExpensesByCategory,
  getExpenseTrends,
  getYearlyComparison,
  getDashboardSummary,
} from "../controllers/analytics.js";

const router = express.Router();

// All routes need authentication
router.use(protect);

// Dashboard summary
router.get("/dashboard", getDashboardSummary);

// Time period summaries
router.get("/expenses/time-summary", getExpensesByTimePeriod);
router.get("/expenses/period-detail", getExpensesForPeriod);

// Category breakdown
router.get("/expenses/category-breakdown", getExpensesByCategory);

// Trends and comparisons
router.get("/expenses/trends", getExpenseTrends);
router.get("/expenses/yearly-comparison", getYearlyComparison);

export default router;
