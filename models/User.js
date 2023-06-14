const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        email: { type: String, required: true },
        password: { type: String, required: true },
        otp: String,
        otpExpiry: Date,
    }
)

const UserModel = mongoose.model("users", UserSchema);

module.exports = UserModel;