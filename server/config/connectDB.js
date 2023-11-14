import mongoose from 'mongoose';

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log(`MongoDB connected: ${mongoose.connection.host}`);
    } catch (error) {
        console.error(`MongoDB connection error: ${error}`);
    }
};

export default connectDB;
