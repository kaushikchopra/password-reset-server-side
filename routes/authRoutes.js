import express from 'express';
import { body } from 'express-validator';
import {
    signup,
    login,
    forgotPassword,
    resetPassword,
    userData
} from '../controllers/authController.js';

const router = express.Router();

// Signup route
router.post(
    '/signup',
    [
        body('name', 'Please include a valid username').isLength({
            min: 6,
        }),
        body('email', 'Please include a valid email Id').isEmail(),
        body('password', 'Please enter a password with 8 or more characters').isLength({
            min: 8,
        }),
    ],
    signup
);

// Login route
router.post(
    '/login',
    [
        body('email', 'Please include a valid email Id').isEmail(),
        body('password', 'Password is required').exists(),
    ],
    login
);

// Forgot Password route
router.post(
    '/forgot-password',
    [
        body('email', 'Please include a valid email Id').isEmail(),
    ],
    forgotPassword
);

// Reset Password route
router.put(
    '/reset-password/:token',
    [
        body('newPassword', 'New Password must be at least 8 characters long').isLength({ min: 8 }),
        body('confirmPassword', 'Confirm Password must be at least 8 characters long').isLength({ min: 8 })
    ],
    resetPassword
);


export default router;
