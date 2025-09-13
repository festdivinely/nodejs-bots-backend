import mongoose from "mongoose";
import crypto from "crypto";
import { BotMarket, PlatformType } from "./botTemplateModel.js";

export const BotStatus = {
  RUNNING_MOMENTARILY: "running momentarily",
  RUNNING_PERPETUALLY: "running perpetually",
  STOPPED: "stopped",
  PAUSED: "paused",
};

export const AccountState = {
  DEMO: "demo",
  REAL: "real",
};

// Encryption key from environment (must be 32 bytes for AES-256-GCM)
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
const IV_LENGTH = 12; // GCM requires a 12-byte IV
const AUTH_TAG_LENGTH = 16; // GCM auth tag length

// Encrypt API key data
function encryptApiKey(data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    encryptedData: encrypted,
    authTag: authTag.toString("hex"),
  };
}

// Decrypt API key data
function decryptApiKey(encryptedObj) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    ENCRYPTION_KEY,
    Buffer.from(encryptedObj.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(encryptedObj.authTag, "hex"));
  let decrypted = decipher.update(encryptedObj.encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

const UserRobotSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: [true, "User ID is required"],
    index: true
  },
  template: {
    refId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BotTemplate",
      required: [true, "Template ID is required"]
    },
    snapshot: {
      name: { type: String },
      description: { type: String },
      image: { type: String },
      price: { type: Number },
      market: {
        type: String,
        enum: Object.values(BotMarket),
        required: [true, "Market type is required"]
      },
      risk: { type: String },
      platform: {
        type: String,
        enum: Object.values(PlatformType),
        required: [true, "Broker platform is required"]
      }
    }
  },
  config: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
    validate: {
      validator: function (v) {
        return (
          v &&
          typeof v === "object" &&
          v.risk_level !== undefined &&
          typeof v.risk_level === "number" &&
          v.risk_level >= 0 &&
          v.risk_level <= 100 &&
          v.accountState !== undefined &&
          Object.values(AccountState).includes(v.accountState)
        );
      },
      message: "Config must be an object with a valid risk_level (number between 0 and 100) and accountState (demo or real)"
    }
  },
  apiKeys: [
    {
      platform: {
        type: String,
        enum: Object.values(PlatformType)
      },
      encryptedData: { type: String },
      iv: { type: String },
      authTag: { type: String }
    }
  ],
  purchased: { type: Boolean, default: false },
  transactionId: { type: String },
  status: {
    type: String,
    enum: Object.values(BotStatus),
    default: BotStatus.STOPPED
  },
  accountState: {
    type: String,
    enum: Object.values(AccountState),
    required: [true, "Account state (demo or real) is required"]
  },
  progress: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  runHistory: [
    {
      action: { type: String, required: true },
      timestamp: { type: Date, default: Date.now },
      progressSnapshot: { type: mongoose.Schema.Types.Mixed }
    }
  ],
  lastUpdated: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserRobotSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Validate apiKeys against template platform if provided
UserRobotSchema.pre("validate", function (next) {
  if (this.apiKeys && this.apiKeys.length > 0) {
    const validPlatform = this.template.snapshot.platform;
    const invalidPlatforms = this.apiKeys.some(key => key.platform !== validPlatform);
    if (invalidPlatforms) {
      return next(new Error("All API keys must match the broker platform defined in the bot template"));
    }
  }
  next();
});

// Encrypt apiKeys before saving if provided
UserRobotSchema.pre("save", function (next) {
  if (this.isModified("apiKeys") && this.apiKeys.length > 0) {
    this.apiKeys = this.apiKeys.map(key => {
      if (!key.encryptedData && key.data) {
        const encrypted = encryptApiKey(key.data);
        return {
          platform: key.platform,
          encryptedData: encrypted.encryptedData,
          iv: encrypted.iv,
          authTag: encrypted.authTag
        };
      }
      return key;
    });
  }
  next();
});

// Method to get decrypted apiKeys
UserRobotSchema.methods.getDecryptedApiKeys = function () {
  return this.apiKeys.map(key => ({
    platform: key.platform,
    data: decryptApiKey(key)
  }));
};

UserRobotSchema.index({ userId: 1, "template.refId": 1 });

export default mongoose.model("UserRobot", UserRobotSchema);