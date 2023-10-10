import express from 'express';
import cors from 'cors';
import authRoutes from './routes/authRoutes.js';
import { databaseConnection } from './db.js';
import authMiddleware from './middlewares/authMiddleware.js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

databaseConnection();

app.use('/dashboard', authMiddleware)
app.use('/api/auth', authRoutes);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
