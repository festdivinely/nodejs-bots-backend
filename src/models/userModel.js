import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { logger } from "../logger/logger.js";
import crypto from "crypto";
import ms from "ms";

const privateKey = Buffer.from(process.env.PRIVATE_KEY, "base64").toString("utf-8");
const ISSUER = process.env.ISSUER || "quantumrobots.com";
const AUDIENCE = process.env.AUDIENCE || "api.quantumrobots.com";

const UserRole = {
    USER: "user",
    ADMIN: "admin",
};

const KYCStatus = {
    PENDING: "pending",
    VERIFIED: "verified",
    REJECTED: "rejected",
};

const RiskProfile = {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
};

const SessionSchema = new mongoose.Schema({
    token: { type: String, required: true },
    expires: { type: Date, required: true },
    deviceInfo: { type: String },
    fingerprint: { type: String },
    ip: { type: String },
    country: { type: String },
    used: { type: Boolean, default: false },
    csrfToken: { type: String },
    createdAt: { type: Date, default: Date.now },
}, { _id: false });

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required"],
        unique: true,
        minlength: [3, "Username must be at least 3 characters"],
        match: [/^[a-zA-Z0-9_-]{3,}$/, "Username can only contain letters, numbers, underscores, and hyphens"],
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        lowercase: true,
        match: [/^[\w.-]+@[a-zA-Z\d-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$/, "Please enter a valid email address"],
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [8, "Password must be at least 8 characters"],
    },
    profileImage: { type: String, default: "" },
    role: { type: String, enum: Object.values(UserRole), default: UserRole.USER },
    isActive: { type: Boolean, default: false },
    lastLogin: { type: Date },
    lastLoginIp: { type: String },
    lastLoginDevice: { type: String },
    sessions: { type: [SessionSchema], default: [] },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    emailResetToken: { type: String },
    emailResetExpires: { type: Date },
    usernameResetToken: { type: String },
    usernameResetExpires: { type: Date },
    emailVerifyToken: { type: String },
    emailVerifyExpires: { type: Date },
    deviceVerifyToken: { type: String },
    deviceVerifyExpires: { type: Date },
    deviceVerifyFingerprint: { type: String },
    robots: {
        type: [{ type: mongoose.Schema.Types.ObjectId, ref: "UserRobot" }],
        default: []
    },
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    middleName: { type: String, trim: true },
    dateOfBirth: { type: String, match: [/^\d{4}-\d{2}-\d{2}$/, "Date of birth must be in YYYY-MM-DD format"] },
    gender: { type: String, enum: ["male", "female", "other"] },
    phoneNumber: { type: String, match: [/^\+?[1-9]\d{1,14}$/, "Phone number must be in E.164 format"] },
    alternatePhone: { type: String, match: [/^\+?[1-9]\d{1,14}$/, "Alternate phone number must be in E.164 format"] },
    addressLine1: { type: String },
    addressLine2: { type: String },
    city: { type: String },
    state: { type: String },
    zipcode: { type: String },
    country: { type: String, uppercase: true },
    currencyPreference: { type: String, minlength: 3, maxlength: 3, uppercase: true },
    bankAccountNumber: { type: String },
    bankName: { type: String },
    bankSwiftCode: { type: String },
    paymentMethods: { type: [String], default: [] },
    nationalIdNumber: { type: String },
    passportNumber: { type: String },
    driverLicenseNumber: { type: String },
    kycStatus: { type: String, enum: Object.values(KYCStatus), default: KYCStatus.PENDING },
    riskProfile: { type: String, enum: Object.values(RiskProfile) },
    twoFactorEnabled: { type: Boolean, default: false },
    preferredLanguage: { type: String, minlength: 2, maxlength: 5 },
    notificationPreferences: { type: [String], default: [] },
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

UserSchema.index({ sessions: 1 });

UserSchema.virtual("id").get(function () {
    return this._id.toHexString();
});

UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        logger.info("Password hashed successfully", { userId: this._id?.toString(), email: this.email });
        next();
    } catch (error) {
        logger.error("Failed to hash password", { userId: this._id?.toString(), email: this.email, error: error.message });
        next(error);
    }
});

UserSchema.methods.generateAccessToken = function () {
    try {
        const token = jwt.sign(
            { userId: this._id.toString(), iss: ISSUER, aud: AUDIENCE },
            privateKey,
            { expiresIn: "15m", algorithm: "RS256" }
        );
        logger.info("Access token generated", { userId: this._id.toString(), email: this.email });
        return token;
    } catch (error) {
        logger.error("Failed to generate access token", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.generateRefreshToken = async function (fingerprint, ip, country, deviceInfo) {
    try {
        const jti = uuidv4();
        const token = jwt.sign(
            { userId: this._id.toString(), jti, iss: ISSUER, aud: AUDIENCE },
            privateKey,
            { expiresIn: "15d", algorithm: "RS256" }
        );
        const expires = new Date(Date.now() + ms("15d"));
        const csrfToken = crypto.randomBytes(32).toString("hex");
        const session = {
            token,
            expires,
            deviceInfo,
            fingerprint,
            ip,
            country,
            used: false,
            csrfToken,
            createdAt: new Date(),
        };
        this.sessions.push(session);
        logger.info("Refresh token generated", { userId: this._id.toString(), email: this.email, jti, fingerprint });
        return token;
    } catch (error) {
        logger.error("Failed to generate refresh token", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.generateEmailVerifyToken = async function () {
    try {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let token = "";
        for (let i = 0; i < 6; i++) {
            token += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        this.emailVerifyToken = token;
        this.emailVerifyExpires = new Date(Date.now() + ms("15m"));
        logger.info("Email verification token generated", { userId: this._id.toString(), email: this.email });
        return token;
    } catch (error) {
        logger.error("Failed to generate email verification token", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.generatePasswordResetToken = async function () {
    try {
        const token = jwt.sign(
            { userId: this._id.toString(), purpose: "password_reset", iss: ISSUER, aud: AUDIENCE },
            privateKey,
            { expiresIn: "15m", algorithm: "RS256" }
        );
        this.passwordResetToken = token;
        this.passwordResetExpires = new Date(Date.now() + ms("15m"));
        logger.info("Password reset token generated", { userId: this._id.toString(), email: this.email });
        return token;
    } catch (error) {
        logger.error("Failed to generate password reset token", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.verifyPassword = async function (candidatePassword) {
    try {
        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        if (!isMatch) {
            logger.warn("Failed password verification attempt", { userId: this._id?.toString(), email: this.email });
        }
        return isMatch;
    } catch (error) {
        logger.error("Error during password verification", { userId: this._id?.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.cleanSessions = async function () {
    this.sessions = this.sessions.filter(s => s.expires > new Date() && !s.used);
    await this.save();
};

UserSchema.methods.generateDeviceVerifyToken = async function (fingerprint) {
    const otp = crypto.randomBytes(3).toString("hex").toUpperCase();
    const hashedOtp = await bcrypt.hash(otp, 10);
    this.deviceVerifyToken = hashedOtp;
    this.deviceVerifyExpires = new Date(Date.now() + ms("5m"));
    this.deviceVerifyFingerprint = fingerprint;
    logger.info("Device verify token generated", { userId: this._id.toString(), email: this.email, fingerprint });
    return otp;
};

export default mongoose.model("User", UserSchema);