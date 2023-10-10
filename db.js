import mongoose from "mongoose";

export async function databaseConnection() {
    const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    }

    // Connect to MongoDB Atlas
    const dbURI = process.env.MONGO_URI;

    try {
        mongoose.connect(dbURI, options)
        console.log('Connected to MongoDB Atlas');
    } catch (error) {
        console.error(`MongoDB connection error: ${error}`);
    }
}