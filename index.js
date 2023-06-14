const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');

const UserModel = require('./models/User')
const ShortUrl = require('./models/shortUrl')

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log("DB Connection Successful"))
    .catch((err) => console.log(err));

app.get("/", async (req, res) => {
    res.send("Day44 Backend")
})


app.post("/signup", async (req, res) => {
    const email = req.body.email;
    const user = await UserModel.findOne({ email });
    if (user) {
        return res.status(404).json({ message: 'Account Already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const newUser = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
    });

    try {
        const savedUser = await newUser.save();
        res.status(200).json({ message: `Account Created Successfully` });
    } catch (err) {
        res.status(500).json(err);
    }
})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid Credentials' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

        res.status(200).json({ token: token, user: user, message: `Login Successful` });
    }
    catch (error) {
        res.status(500).json({ message: 'Internal Server error' });
    }

})

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    // Find user by email
    const user = await UserModel.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP

    const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false });
    const otpExpiry = Date.now() + 600000; // 10 minutes

    // Save  OTP, and their expiry to user
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // Send password reset email with OTP
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'joshuasujith14@gmail.com',
            pass: process.env.PASS_KEY,
        },
    });

    const mailOptions = {
        from: 'joshuasujith14@gmail.com',
        to: email,
        subject: 'Password Reset',
        text: `You are receiving this email because you requested a password reset. Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.status(500).json({ message: 'Failed to send password reset email' });
        }

        res.json({ message: 'Password reset email sent' });
    });
});

app.post('/reset-password', async (req, res) => {
    const { otp, newPassword } = req.body;

    // Find user by reset token and OTP
    const user = await UserModel.findOne({
        otp,
        otpExpiry: { $gt: Date.now() },
    });

    if (!user) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Update user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
});

app.get('/allUrls', async (req, res) => {
    try {
        const AllUrls = await ShortUrl.find()
        res.status(200).json(AllUrls);
    } catch (err) {
        res.status(500).json(err);
    }

})

app.post('/shortUrls', async (req, res) => {
    const url = await ShortUrl.create({ name: req.body.name, full: req.body.fullUrl })

    res.json({ url: url, message: 'Short URL Created Successfully' })
})

app.get('/:shortUrl', async (req, res) => {
    const shortUrl = await ShortUrl.findOne({ short: req.params.shortUrl })
    if (shortUrl == null) return res.sendStatus(404)

    shortUrl.clicks++
    shortUrl.save()

    res.status(200).json(shortUrl.full);
})

app.get('/url/daily-count', async (req, res) => {
    try {
        const currentDate = new Date();
        const currentMonth = currentDate.getMonth(); // Get the current month
        const currentYear = currentDate.getFullYear(); // Get the current year

        const startDate = new Date(currentYear, currentMonth, 1); // Set the start date to the first day of the current month
        const endDate = new Date(currentYear, currentMonth + 1, 0); // Set the end date to the last day of the current month

        const result = await ShortUrl.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: startDate,
                        $lte: endDate,
                    },
                },
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: '$createdAt' },
                    },
                    count: { $sum: 1 },
                },
            },
            {
                $sort: { _id: 1 },
            },
        ]);

        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.listen(5000, () => {
    console.log("Backend Server is Running")
})