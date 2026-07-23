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
      default: "free",
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
    // saasGenerationsCount: { type: Number, default: 0 },
    // User Schema field addition

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

//     <!-- <div class="flex justify-between items-center mb-2">
//       <span class="text-slate-300 font-semibold"
//         >🔑 Your Domain Verification Tag</span
//       >
//       <span
//         class="text-xs bg-slate-700 text-emerald-400 px-2 py-0.5 rounded uppercase font-bold"
//         ><%= user.planTier %> Plan</span
//       >
//     </div> -->
//     <!-- <p class="text-xs text-slate-400 mb-2">
//       Add this tag inside any SaaS site's
//       <code class="text-cyan-300">&lt;head&gt;</code> to verify ownership
//       before your first crawl:
//     </p>
//     <div
//       class="bg-slate-950 p-2 rounded font-mono text-xs text-emerald-400 select-all overflow-x-auto"
//     >
//       &lt;meta name="faastsaas-verification" content="<%=
//       user.verificationToken %>"&gt;
//     </div> -->

//           <!-- <% if (user.planTier === 'free') { %>
//     <div class="space-y-1 pt-2 border-t border-slate-700">
//         <div class="flex justify-between text-slate-300">
//             <span>Verified Domains:</span>
//             <span><%= user.verifiedDomainsCount %> / 1</span>
//         </div>

//     </div>
//     <a href="/pricing" class="block text-center m-3 bg-slate-700 hover:bg-slate-600 text-slate-200 py-1.5 rounded transition">
//         Upgrade Plan
//     </a>
// <% } %> -->
