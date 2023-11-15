
import asyncHandler from 'express-async-handler'
import User from '../models/User.js'
import jwt from 'jsonwebtoken'
import bcrypt from "bcrypt";
import winston from 'winston'


const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

const logger = winston.createLogger({
    level: "info",
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: "logs/app.log" }),
    ],
});

export const registerUser = asyncHandler(async (req, res) => {
    const { fullname, email, password } = req.body;

    // Validation
    if (!fullname || !email || !password) {
        logger.error("Validation Error: Please fill in all required fields");
        return res.status(400).json({ error: "Please fill in all required fields" });
    }
    if (password.length < 6) {
        logger.error("Validation Error: Şifre en az 6 karakter olmalıdır");
        return res.status(400).json({ error: "Şifre en az 6 karakter olmalıdır" });
    }

    // Check if user email already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
        logger.error("User Exists: Email has already been registered");
        return res.status(400).json({ error: "Email has already been registered" });
    }

    // Create a new user
    const user = await User.create({
        personal_info: {
            fullname,
            email,
            password,
        }

    });

    if (user) {
        const { _id, fullName, email, photo, phone, bio } = user;

        // Generate Token after user creation
        const token = generateToken(user._id);
        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 Day
            sameSite: "none",
            secure: true,
        });
        logger.info("User Registered: User registered successfully");
        return res.status(201).json({
            _id,
            fullName,
            email,
            photo,
            phone,
            bio,
            token,
        });
    } else {
        logger.error("Invalid User Data: Invalid user data");
        return res.status(400).json({ error: "Invalid user data" });
    }
});

export const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate user
    if (!email || !password) {
        logger.error("Validation Error: Please add email and password");
        return res.status(400).json({ error: "Please add email and password" });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
        logger.error("User Not Found: User not found, please sign up");
        return res.status(400).json({ error: "User not found, please sign up" });
    }

    // User exists, check if the password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (passwordIsCorrect) {
        const { _id, fullname, email, profile_img, bio } = user;
        const token = generateToken(_id);

        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 Day
            sameSite: "none",
            secure: true,
        });
        logger.info("User Logged In: User logged in successfully");
        return res.status(200).json({
            _id,
            fullname,
            email,
            profile_img,
            bio,
            token,
        });
    } else {
        logger.error("Invalid Credentials: Invalid email or password");
        return res.status(400).json({ error: "Invalid email or password" });
    }
});

export const logoutUser = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    logger.info("User Logged Out: User logged out successfully");
    return res.status(200).json({ message: "Successfully Logged Out" });
});

export const getUser = asyncHandler(async (req, res) => {
    // User.findById işlemi asenkron olduğu için await kullanmalısınız.
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, photo, phone, bio } = user;

        logger.info("User Info Retrieved: User information retrieved successfully");
        return res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
        });
    } else {
        logger.error("User Not Found: Kullanıcı bulunamadı");
        return res.status(400).json({ error: "Kullanıcı bulunamadı" });
    }
});

// Get Login Status
export const loginStatus = asyncHandler(async(req,res) => {
    const token = req.cookies.token
    if (!token) {
        return res.json(false)
    }
    // Verify Token
    const verified = jwt.verify(token,process.env.JWT_SECRET)
    if (verified) {
        return res.json(true)
    }
})

export const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        // Kullanıcıdan gelen güncelleme verilerini alın
        const { name, email, photo, phone, bio } = user;

        // Kullanıcı bilgilerini güncelleyin
        user.email = req.body.email || email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.photo = req.body.photo || photo;
        user.bio = req.body.bio || bio;

        // Kullanıcı bilgilerini kaydedin
        const updatedUser = await user.save();

        // Güncellenmiş kullanıcı bilgilerini yanıt olarak gönderin
        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            photo: updatedUser.photo,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
        });
    } else {
        res.status(404).json({ error: "User not found" });
    }
});
