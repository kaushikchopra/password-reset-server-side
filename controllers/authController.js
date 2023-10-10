import { User } from '../models/User.js'
import { PasswordResetToken } from '../models/PasswordResetToken.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import { validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import { clientURL } from '../config/config.js';

// Signup
const signup = async (req, res) => {
    try {
        // If there are errors, return Bad request and the errors
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        // Check if the user already exists
        const user = await User.findOne({ email });

        if (user) {
            return res.status(400).json({ error: 'User already exists. Please use another email Id' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user
        const newUser = await User.create({
            name: name,
            email: email,
            password: hashedPassword
        });

        // Generate a signup token
        const data = {
            userId: newUser._id,
        }
        const token = jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '1h' })

        res.json({ status: 'User created successfully!', token });

    } catch (error) {

        res.status(500).send('Internal Server Error');
    }
}

// Login
const login = async (req, res) => {
    try {
        // If there are errors, return Bad request and the errors
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        // Check if the user already exists
        const user = await User.findOne({ email });

        // User does not exists
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Compare the password with hashed password
        const passwordCompare = await bcrypt.compare(password, user.password)

        // Password does not match
        if (!passwordCompare) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate a login token
        const data = {
            userId: user._id,
        }
        const token = jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '1h' })

        res.json({ status: 'User logged in successfully!', token });

    } catch (error) {

        res.status(500).send('Internal Server Error');
    }
}

// Forgot Password
const forgotPassword = async (req, res) => {
    try {
        // If there are errors, return Bad request and the errors
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email } = req.body;

        // Check if the user already exists
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'Email ID does not exist' });
        }

        // Generate a password reset token
        const data = {
            userId: user._id,
        };
        const token = jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '1h' });

        const passwordResetToken = new PasswordResetToken({
            user: user._id,
            token,
        });

        await passwordResetToken.save();

        //Nodemailer configuration to send mails using gmail
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            },
            tls: {
                ciphers: 'SSLv3'
            }
        });

        // Compose an email to reset the password
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <p>You are receiving this email because you (or someone else) has requested a password reset for your account.</p>
                <p>Please click on the following button to reset your password.</p>
                <a href=${clientURL}/reset-password/${token} style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p>If you did not request this, please ignore this mail, and your password will remain unchanged.</p>`
        };

        // Send the email using the created transporter
        const mailSentResponse = await transporter.sendMail(mailOptions);

        if (mailSentResponse) {
            return res.status(200).json({
                status: "Password reset email sent"
            });
        } else {
            return res.status(400).json({
                error: "Error sending password reset email"
            });
        }

    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
};


// Reset Password
const resetPassword = async (req, res) => {

    try {
        // If there are errors, return Bad request and the errors
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { token } = req.params;
        const { newPassword, confirmPassword } = req.body;

        // Find the password reset token
        const passwordResetToken = await PasswordResetToken.findOne({ token });

        if (!passwordResetToken) {
            return res.status(400).json({ error: 'Invalid or expired Token' })
        }

        // Check if the token is still valid
        const tokenData = jwt.verify(token, process.env.JWT_SECRET);

        if (!tokenData) {
            return res.status(400).json({ error: 'Invalid or expired Token' })
        }

        // Find the user associated with the token
        const user = await User.findById(tokenData.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' })
        }

        // Check if newPassword and confirmPassword match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'Password do not match' });
        }

        //Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        //Update the user's password
        user.password = hashedPassword;
        await user.save();

        // Delete the password reset token
        await PasswordResetToken.findOneAndDelete({ token: token });

        res.json({ status: 'Password reset successfully' });

    } catch (error) {

        res.status(500).send('Internal Server Error');
    }
}

// Accessing the user data from the req.user of authMiddleware
const userData = (req, res) => {
    // Access user data from req.user
    const userData = req.user;

    // Use userData in your response or perform other actions
    res.json({ user: userData });
}
export { signup, login, forgotPassword, resetPassword, userData };