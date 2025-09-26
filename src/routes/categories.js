/**
 * @swagger
 * tags:
 *   name: Categories
 *   description: Category management endpoints
 */

/**
 * @swagger
 * /api/v1/categories:
 *   get:
 *     summary: Get all categories
 *     description: Retrieve all categories for the authenticated user
 *     tags: [Categories]
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
 *         description: Number of categories per page
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search categories by name
 *       - in: query
 *         name: isActive
 *         schema:
 *           type: boolean
 *         description: Filter by active status
 *     responses:
 *       200:
 *         description: Categories retrieved successfully
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
 *                     $ref: '#/components/schemas/Category'
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
 *     summary: Create a new category
 *     description: Create a new expense category
 *     tags: [Categories]
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
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 50
 *                 description: Category name
 *                 example: "Business Travel"
 *               description:
 *                 type: string
 *                 maxLength: 200
 *                 description: Category description
 *                 example: "Expenses related to business travel and transportation"
 *               color:
 *                 type: string
 *                 pattern: "^#[0-9A-Fa-f]{6}$"
 *                 description: Category color in hex format
 *                 example: "#3B82F6"
 *     responses:
 *       201:
 *         description: Category created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Category'
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
 *         description: Category name already exists
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
 * /api/v1/categories/{id}:
 *   get:
 *     summary: Get category by ID
 *     description: Retrieve a specific category by its ID
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *     responses:
 *       200:
 *         description: Category retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Category'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Category not found
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
 *     summary: Update category
 *     description: Update an existing category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
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
 *                 maxLength: 50
 *                 description: Category name
 *                 example: "Business Travel"
 *               description:
 *                 type: string
 *                 maxLength: 200
 *                 description: Category description
 *                 example: "Expenses related to business travel and transportation"
 *               color:
 *                 type: string
 *                 pattern: "^#[0-9A-Fa-f]{6}$"
 *                 description: Category color in hex format
 *                 example: "#3B82F6"
 *               isActive:
 *                 type: boolean
 *                 description: Whether the category is active
 *                 example: true
 *     responses:
 *       200:
 *         description: Category updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Category'
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
 *         description: Category not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Category name already exists
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
 *     summary: Delete category
 *     description: Delete a category (only if no expenses are associated)
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *     responses:
 *       200:
 *         description: Category deleted successfully
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
 *                   example: "Category deleted successfully"
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Category not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Cannot delete category with associated expenses
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
 * /api/v1/categories/{id}/budget:
 *   post:
 *     summary: Add budget limit to category
 *     description: Add a budget limit for a specific period to a category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - period
 *               - amount
 *             properties:
 *               period:
 *                 type: string
 *                 enum: ["daily", "weekly", "monthly", "yearly"]
 *                 description: Budget period
 *                 example: "monthly"
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *                 description: Budget limit amount
 *                 example: 1000.00
 *     responses:
 *       201:
 *         description: Budget limit added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Category'
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
 *         description: Category not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Budget limit for this period already exists
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
 * /api/v1/categories/{id}/budget/{budgetId}:
 *   put:
 *     summary: Update budget limit
 *     description: Update an existing budget limit for a category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *       - in: path
 *         name: budgetId
 *         required: true
 *         schema:
 *           type: string
 *         description: Budget limit ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               period:
 *                 type: string
 *                 enum: ["daily", "weekly", "monthly", "yearly"]
 *                 description: Budget period
 *                 example: "monthly"
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *                 description: Budget limit amount
 *                 example: 1000.00
 *     responses:
 *       200:
 *         description: Budget limit updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/Category'
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
 *         description: Category or budget limit not found
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
 *     summary: Delete budget limit
 *     description: Remove a budget limit from a category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Category ID
 *       - in: path
 *         name: budgetId
 *         required: true
 *         schema:
 *           type: string
 *         description: Budget limit ID
 *     responses:
 *       200:
 *         description: Budget limit deleted successfully
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
 *                   example: "Budget limit deleted successfully"
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Category or budget limit not found
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
import {
  getCategories,
  getCategory,
  createCategory,
  updateCategory,
  deleteCategory,
  addBudgetLimit,
  updateBudgetLimit,
  deleteBudgetLimit,
  getBudgetUsage,
  updateBudgetUsage,
  getCategorySummary,
} from "../controllers/categories.js";

import { protect, authorize, protectInternalAPI } from "../middleware/auth.js";
import { modifyDataLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

// All routes require authentication
router.use(protect);

// Category summary route
router.get("/summary", getCategorySummary);

// Public routes (accessible by all logged in users)
router.get("/", getCategories);
router.get("/:id", getCategory);
router.get("/:id/budget/usage", getBudgetUsage);

// Admin only routes
router.post("/", modifyDataLimiter, authorize("admin"), createCategory);
router.put("/:id", modifyDataLimiter, authorize("admin"), updateCategory);
router.delete("/:id", modifyDataLimiter, authorize("admin"), deleteCategory);

// Budget management routes (admin only)
router.post("/:id/budget", modifyDataLimiter, authorize("admin"), addBudgetLimit);
router.put("/:id/budget/:budgetId", modifyDataLimiter, authorize("admin"), updateBudgetLimit);
router.delete("/:id/budget/:budgetId", modifyDataLimiter, authorize("admin"), deleteBudgetLimit);

// Internal service routes (protected by API token)
// Allow either admin user or internal API to access
router.post("/:id/budget/update-usage", (req, res, next) => {
  // First check for internal API token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    const token = req.headers.authorization.split(" ")[1];
    if (token === process.env.API_INTERNAL_TOKEN) {
      req.isInternalRequest = true;
      return updateBudgetUsage(req, res, next);
    }
  }

  // If not internal request, check for admin authorization
  return authorize("admin")(req, res, (err) => {
    if (err) return next(err);
    updateBudgetUsage(req, res, next);
  });
});

export default router;
