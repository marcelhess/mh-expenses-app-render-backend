import express from "express";
import {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
} from "../controllers/users.js";

import { protect, authorize } from "../middleware/auth.js";
import { modifyDataLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

router.use(protect);
router.use(authorize("admin"));

router.route("/").get(getUsers).post(modifyDataLimiter, createUser);

router.route("/:id").get(getUser).put(modifyDataLimiter, updateUser).delete(modifyDataLimiter, deleteUser);

export default router;
