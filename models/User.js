const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

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
      default: "starter",
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
  },
  { timestamps: true },
);

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
