import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
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

const DeviceStatus = {
    NOT_CONFIRMED: "NOT CONFIRMED",
    YES_IT_ME: "YES IT ME"
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

const DeviceSchema = new mongoose.Schema({
    fingerprint: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: Object.values(DeviceStatus),
        default: DeviceStatus.NOT_CONFIRMED,
        required: true
    },
    deviceInfo: {
        type: String,
        required: true
    },
    ip: {
        type: String,
        required: true
    },
    country: {
        type: String,
        default: 'unknown'
    },
    verificationCode: {
        type: String
    },
    verificationCodeExpires: {
        type: Date
    },
    verifiedAt: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date
    }
}, { _id: false });

// Add TTL index for devices with expiresAt
DeviceSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const BackupCodeLogSchema = new mongoose.Schema({
    usedAt: {
        type: Date,
        default: Date.now,
        required: true
    },
    ip: {
        type: String,
        required: true
    },
    deviceInfo: {
        type: String,
        required: true
    },
    country: {
        type: String,
        default: 'unknown'
    },
    remainingCodes: {
        type: Number,
        required: true
    }
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

    // TOTP Fields
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String
    },
    twoFactorBackupCodes: [{
        type: String,
        select: false
    }],
    twoFactorSetupCompleted: {
        type: Boolean,
        default: false
    },
    pendingTOTPEnable: {
        type: Boolean,
        default: false
    },
    backupCodeLogs: {
        type: [BackupCodeLogSchema],
        default: () => [],
        select: false
    },
    lastBackupCodeUsed: {
        type: Date
    },

    profileImage: { type: String, default: "" },
    role: { type: String, enum: Object.values(UserRole), default: UserRole.USER },
    isActive: { type: Boolean, default: false },
    lastLogin: { type: Date },
    lastLoginIp: { type: String },
    lastLoginDevice: { type: String },
    sessions: { type: [SessionSchema], default: [] },
    devices: { type: [DeviceSchema], default: [] },

    // CODE-BASED FIELDS ONLY
    passwordResetCode: { type: String },
    passwordResetCodeExpires: { type: Date },
    emailVerifyCode: { type: String },
    emailVerifyCodeExpires: { type: Date },

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
    preferredLanguage: { type: String, minlength: 2, maxlength: 5 },
    notificationPreferences: { type: [String], default: [] },
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Add TTL index for unverified users (24 hours)
UserSchema.index({ createdAt: 1 }, {
    expireAfterSeconds: 86400,
    partialFilterExpression: { isActive: false }
});

UserSchema.index({ sessions: 1 });

UserSchema.virtual("id").get(function () {
    return this._id.toHexString();
});

// ========== PRE-SAVE HOOKS ==========
UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        console.info("Password hashed successfully", { userId: this._id?.toString(), email: this.email });
        next();
    } catch (error) {
        console.error("Failed to hash password", { userId: this._id?.toString(), email: this.email, error: error.message });
        next(error);
    }
});

UserSchema.pre("save", function (next) {
    // Initialize backupCodeLogs if undefined (important for existing users)
    if (!this.backupCodeLogs) {
        this.backupCodeLogs = [];
    }
    next();
});

// ========== BACKUP CODE METHODS ==========
UserSchema.methods.verifyBackupCode = async function (backupCode, ip, deviceInfo, country) {
    try {
        // Check if backup codes exist
        if (!this.twoFactorBackupCodes || this.twoFactorBackupCodes.length === 0) {
            console.warn("No backup codes available", {
                userId: this._id.toString(),
                email: this.email
            });
            return { valid: false, index: -1, remainingCodes: 0 };
        }

        // Compare the backup code with each hashed backup code
        for (let i = 0; i < this.twoFactorBackupCodes.length; i++) {
            const match = await bcrypt.compare(backupCode, this.twoFactorBackupCodes[i]);
            if (match) {
                console.info("Backup code verified successfully", {
                    userId: this._id.toString(),
                    email: this.email,
                    codeIndex: i,
                    remainingBeforeUse: this.twoFactorBackupCodes.length
                });
                return {
                    valid: true,
                    index: i,
                    remainingCodes: this.twoFactorBackupCodes.length
                };
            }
        }

        console.warn("Invalid backup code attempt", {
            userId: this._id.toString(),
            email: this.email,
            ip,
            deviceInfo,
            country
        });
        return { valid: false, index: -1, remainingCodes: this.twoFactorBackupCodes.length };
    } catch (error) {
        console.error("Failed to verify backup code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.useBackupCode = async function (codeIndex, ip, deviceInfo, country) {
    try {
        // Remove the used backup code
        this.twoFactorBackupCodes.splice(codeIndex, 1);

        // Update timestamp
        this.lastBackupCodeUsed = new Date();

        // Initialize backupCodeLogs if undefined (defensive check)
        if (!this.backupCodeLogs) {
            this.backupCodeLogs = [];
        }

        // Log the usage
        this.backupCodeLogs.push({
            usedAt: new Date(),
            ip,
            deviceInfo,
            country,
            remainingCodes: this.twoFactorBackupCodes.length
        });

        // Keep only last 10 logs to prevent unbounded growth
        if (this.backupCodeLogs.length > 10) {
            this.backupCodeLogs = this.backupCodeLogs.slice(-10);
        }

        await this.save();

        console.info("Backup code used and removed", {
            userId: this._id.toString(),
            email: this.email,
            remainingCodes: this.twoFactorBackupCodes.length,
            ip,
            deviceInfo,
            country
        });

        return this.twoFactorBackupCodes.length;
    } catch (error) {
        console.error("Failed to use backup code", {
            userId: this._id.toString(),
            email: this.email,
            codeIndex,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.generateBackupCodes = async function () {
    try {
        // Generate 8 new backup codes
        const backupCodes = Array.from({ length: 8 }, () =>
            Math.random().toString(36).substring(2, 10).toUpperCase()
        );

        // Hash the backup codes (same as passwords)
        const hashedBackupCodes = await Promise.all(
            backupCodes.map(async (code) => await bcrypt.hash(code, 10))
        );

        // Store the hashed codes
        this.twoFactorBackupCodes = hashedBackupCodes;

        // Clear logs when generating new codes
        this.backupCodeLogs = [];
        this.lastBackupCodeUsed = undefined;

        await this.save();

        console.info("New backup codes generated", {
            userId: this._id.toString(),
            email: this.email,
            count: backupCodes.length
        });

        // Return plain codes for user to save (show only once!)
        return backupCodes;
    } catch (error) {
        console.error("Failed to generate backup codes", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.getRemainingBackupCodesCount = function () {
    return this.twoFactorBackupCodes?.length || 0;
};

// ========== AUTHENTICATION TOKEN METHODS ==========
UserSchema.methods.generateAccessToken = function () {
    try {
        const token = jwt.sign(
            { userId: this._id.toString(), iss: ISSUER, aud: AUDIENCE },
            privateKey,
            { expiresIn: "15m", algorithm: "RS256" }
        );
        console.info("Access token generated", { userId: this._id.toString(), email: this.email });
        return token;
    } catch (error) {
        console.error("Failed to generate access token", { userId: this._id.toString(), email: this.email, error: error.message });
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
        await this.save();
        console.info("Refresh token generated", { userId: this._id.toString(), email: this.email, jti, fingerprint });
        return token;
    } catch (error) {
        console.error("Failed to generate refresh token", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

// ========== EMAIL VERIFICATION CODE METHODS ==========
UserSchema.methods.generateEmailVerifyCode = async function () {
    try {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        this.emailVerifyCode = code;
        this.emailVerifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        await this.save();
        console.info("Email verification code generated", {
            userId: this._id.toString(),
            email: this.email
        });
        return code;
    } catch (error) {
        console.error("Failed to generate email verification code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.verifyEmailVerifyCode = async function (code) {
    try {
        const isValid = this.emailVerifyCode === code &&
            this.emailVerifyCodeExpires > new Date();

        if (!isValid) {
            console.warn("Invalid or expired email verification code", {
                userId: this._id.toString(),
                email: this.email,
                providedCode: "[REDACTED]",
                storedCode: this.emailVerifyCode ? "[REDACTED]" : "none",
                expires: this.emailVerifyCodeExpires
            });
            return false;
        }

        console.info("Email verification code verified successfully", {
            userId: this._id.toString(),
            email: this.email
        });
        return true;
    } catch (error) {
        console.error("Failed to verify email verification code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.clearEmailVerifyCode = async function () {
    try {
        this.emailVerifyCode = undefined;
        this.emailVerifyCodeExpires = undefined;
        await this.save();
        console.info("Email verification code cleared", {
            userId: this._id.toString(),
            email: this.email
        });
    } catch (error) {
        console.error("Failed to clear email verification code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

// ========== PASSWORD RESET CODE METHODS ==========
UserSchema.methods.generatePasswordResetCode = async function () {
    try {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        this.passwordResetCode = code;
        this.passwordResetCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        await this.save();
        console.info("Password reset code generated", {
            userId: this._id.toString(),
            email: this.email
        });
        return code;
    } catch (error) {
        console.error("Failed to generate password reset code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.verifyPasswordResetCode = async function (code) {
    try {
        const isValid = this.passwordResetCode === code &&
            this.passwordResetCodeExpires > new Date();

        if (!isValid) {
            console.warn("Invalid or expired password reset code", {
                userId: this._id.toString(),
                email: this.email,
                providedCode: "[REDACTED]",
                storedCode: this.passwordResetCode ? "[REDACTED]" : "none",
                expires: this.passwordResetCodeExpires
            });
            return false;
        }

        console.info("Password reset code verified successfully", {
            userId: this._id.toString(),
            email: this.email
        });
        return true;
    } catch (error) {
        console.error("Failed to verify password reset code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

UserSchema.methods.clearPasswordResetCode = async function () {
    try {
        this.passwordResetCode = undefined;
        this.passwordResetCodeExpires = undefined;
        await this.save();
        console.info("Password reset code cleared", {
            userId: this._id.toString(),
            email: this.email
        });
    } catch (error) {
        console.error("Failed to clear password reset code", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

// ========== PASSWORD & SESSION METHODS ==========
UserSchema.methods.verifyPassword = async function (candidatePassword) {
    try {
        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        if (!isMatch) {
            console.warn("Failed password verification attempt", { userId: this._id?.toString(), email: this.email });
        }
        return isMatch;
    } catch (error) {
        console.error("Error during password verification", { userId: this._id?.toString(), email: this.email, error: error.message });
        throw error;
    }
};

UserSchema.methods.cleanSessions = async function () {
    try {
        this.sessions = this.sessions.filter(s => s.expires > new Date() && !s.used);
        await this.save();
        console.info("Sessions cleaned", { userId: this._id.toString(), email: this.email });
    } catch (error) {
        console.error("Failed to clean sessions", { userId: this._id.toString(), email: this.email, error: error.message });
        throw error;
    }
};

// ========== DEVICE VERIFICATION METHODS ==========
UserSchema.methods.addOrUpdateDeviceVerification = async function (fingerprint, deviceInfo, ip, country) {
    try {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours

        const existingDeviceIndex = this.devices.findIndex(device =>
            device.fingerprint === fingerprint && device.status === DeviceStatus.NOT_CONFIRMED
        );

        if (existingDeviceIndex !== -1) {
            // Update existing device
            this.devices[existingDeviceIndex].verificationCode = verificationCode;
            this.devices[existingDeviceIndex].verificationCodeExpires = verificationCodeExpires;
            this.devices[existingDeviceIndex].expiresAt = expiresAt;
            this.devices[existingDeviceIndex].deviceInfo = deviceInfo;
            this.devices[existingDeviceIndex].ip = ip;
            this.devices[existingDeviceIndex].country = country;
        } else {
            // Add new device
            this.devices.push({
                fingerprint,
                status: DeviceStatus.NOT_CONFIRMED,
                deviceInfo,
                ip,
                country,
                verificationCode,
                verificationCodeExpires,
                createdAt: new Date(),
                expiresAt
            });
        }

        await this.save();
        console.info("Device verification code generated", {
            userId: this._id.toString(),
            email: this.email,
            fingerprint,
            verificationCode: "[REDACTED]"
        });
        return verificationCode;
    } catch (error) {
        console.error("Failed to generate device verification code", {
            userId: this._id.toString(),
            email: this.email,
            fingerprint,
            error: error.message,
        });
        throw error;
    }
};

UserSchema.methods.verifyDeviceCode = async function (fingerprint, verificationCode) {
    try {
        const device = this.devices.find(d =>
            d.fingerprint === fingerprint &&
            d.status === DeviceStatus.NOT_CONFIRMED &&
            d.verificationCode === verificationCode &&
            d.verificationCodeExpires > new Date()
        );

        if (!device) {
            return false;
        }

        // Update device status
        device.status = DeviceStatus.YES_IT_ME;
        device.verifiedAt = new Date();
        device.verificationCode = undefined;
        device.verificationCodeExpires = undefined;
        device.expiresAt = undefined; // Remove TTL

        await this.save();
        console.info("Device verified successfully", {
            userId: this._id.toString(),
            email: this.email,
            fingerprint
        });
        return true;
    } catch (error) {
        console.error("Failed to verify device code", {
            userId: this._id.toString(),
            email: this.email,
            fingerprint,
            error: error.message,
        });
        throw error;
    }
};

UserSchema.methods.isDeviceVerified = function (fingerprint) {
    const device = this.devices.find(d =>
        d.fingerprint === fingerprint && d.status === DeviceStatus.YES_IT_ME
    );
    return !!device;
};

// ========== CLEANUP METHODS ==========
UserSchema.statics.cleanupExpiredUnverifiedUsers = async function () {
    try {
        const result = await this.deleteMany({
            isActive: false,
            createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // 24 hours
        });
        console.info('Cleaned up expired unverified users', { deletedCount: result.deletedCount });
        return result;
    } catch (error) {
        console.error('Failed to cleanup expired unverified users', { error: error.message });
        throw error;
    }
};

// ========== TOTP METHODS ==========
UserSchema.methods.disableTOTP = async function () {
    try {
        this.twoFactorEnabled = false;
        this.twoFactorSecret = undefined;
        this.twoFactorBackupCodes = [];
        this.twoFactorSetupCompleted = false;
        this.backupCodeLogs = [];
        this.lastBackupCodeUsed = undefined;

        await this.save();
        console.info("TOTP disabled successfully", {
            userId: this._id.toString(),
            email: this.email
        });
        return true;
    } catch (error) {
        console.error("Failed to disable TOTP", {
            userId: this._id.toString(),
            email: this.email,
            error: error.message
        });
        throw error;
    }
};

export default mongoose.model("User", UserSchema);