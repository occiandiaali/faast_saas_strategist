const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const SALT_ROUNDS = 12; // Recommended above-moderate security level value for bcrypt

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    // SaaS Subscription tiers: 'free', 'starter', 'pro'
    planTier: {
      type: String,
      enum: ["free", "starter", "pro"],
      default: "pro",
    },
    // Domain Ownership Verification storage
    verifiedUrls: [
      {
        type: String,
        trim: true,
      },
    ],
    // Permanent verification token assigned to user for head-tag checks
    verificationToken: {
      type: String,
      default: () =>
        "faastsaas-verify-" + crypto.randomBytes(12).toString("hex"),
    },
    // Usage counters
    verifiedDomainsCount: { type: Number, default: 0 },
    saasGenerationsCount: { type: Number, default: 0 },
    // Latest addition
    pendingDomain: { type: String, default: null },
    domainVerificationToken: { type: String, default: null },
    maxScans: { type: Number, default: 0 },
    lastQuotaReset: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true },
);

// async Functions Don't Need next(): In modern Mongoose,
// if you define an async function for middleware (async function()),
// Mongoose automatically handles the promise resolution and doesn't require next().
userSchema.pre("save", async function () {
  // 1. Password hashing logic
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
  }

  // 2. Plan Tier / maxScans logic
  if (this.isNew || this.isModified("planTier")) {
    if (this.planTier === "starter") {
      this.maxScans = 20;
    } else if (this.planTier === "pro") {
      this.maxScans = 100;
    } else if (this.planTier === "free") {
      this.maxScans = 1;
    }
  }
});

userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.resetMonthlyQuotasIfNeeded = async function () {
  const now = new Date();
  const lastReset = this.lastQuotaReset
    ? new Date(this.lastQuotaReset)
    : new Date(0);

  // Check if we are in a new calendar month or new year
  const isNewMonth =
    now.getMonth() !== lastReset.getMonth() ||
    now.getFullYear() !== lastReset.getFullYear();

  if (isNewMonth) {
    // Reset generation and domain counts
    this.saasGenerationsCount = 0;
    this.verifiedDomainsCount = 0;

    // Reset maxScans based on their current plan tier
    if (this.planTier === "starter") {
      this.maxScans = 20;
    } else if (this.planTier === "pro") {
      this.maxScans = 100;
    } else {
      this.maxScans = 1; // "free"
    }

    // Update the reset timestamp to the current time
    this.lastQuotaReset = now;

    // Save changes to database
    await this.save();
  }
};

module.exports = mongoose.model("User", userSchema);
