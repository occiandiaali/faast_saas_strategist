require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto = require("crypto"); // For domain verification token generation
const axios = require("axios"); // or native fetch
const User = require("./models/User");
const JSZip = require("jszip");
const path = require("path");
const Stripe = require("stripe");
const { authMiddleware, JWT_SECRET } = require("./middleware/auth");
const {
  checkDomainLimit,
  checkGenerationLimit,
} = require("./middleware/usageLimits");

const connectDB = require("./config/db");

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Atlas connection call
connectDB();

// MUST BE PLACED BEFORE app.use(express.json())!
app.post(
  "/api/webhooks/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (err) {
      console.error(`Webhook Signature Verification Failed: ${err.message}`);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle event types
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const userId = session.client_reference_id || session.metadata.userId;
        const targetPlan = session.metadata.targetPlan || "pro";

        // Upgrade User in DB
        await User.findByIdAndUpdate(userId, {
          planTier: targetPlan,
          stripeCustomerId: session.customer,
          stripeSubscriptionId: session.subscription,
        });
        break;
      }

      case "customer.subscription.deleted": {
        // Revert back to free tier if subscription is canceled
        const subscription = event.data.object;
        await User.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          { planTier: "free" },
        );
        break;
      }

      default:
        // Unhandled event type
        break;
    }

    // Return 200 to acknowledge receipt to Stripe
    res.json({ received: true });
  },
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// --- Auth Routes ---

// Landing Page
app.get("/", (req, res) => {
  res.render("landing");
});

app.get("/index", (req, res) => {
  res.render("index");
});

// Pricing / Subscription Page
app.get("/pricing", (req, res) => {
  res.render("pricing");
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// Register Page
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.send(`
                <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg mb-4 flex items-center gap-2">
                    <span>⚠️ Please provide both email and password.</span>
                </div>
            `);
    }
    const existing = await User.findOne({ email: email.toLowerCase() });

    if (existing) {
      return res.send(`
                <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg mb-4 flex items-center gap-2">
                    <span>⚠️ We cannot register this email address. That's all we know.</span>
                </div>
            `);
    }

    const user = new User({ email, password });
    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });
    // res.redirect("/login");
    // Instruct HTMX to redirect the browser to the protected dashboard
    res.setHeader("HX-Redirect", "/index");
    return res.status(200).send("Success");
  } catch (err) {
    //res.render("register", { error: "Failed to create account" });
    return res.send(`
            <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg mb-4">
                Failed to create account: ${err.message}
            </div>
        `);
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({
      email: email ? email.toLowerCase() : "",
    });
    if (!user || !(await user.comparePassword(password))) {
      return res.send(`
                <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg mb-4 flex items-center gap-2">
                    <span>⚠️ Invalid email or password credential.</span>
                </div>
            `);
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });
    // res.redirect("/generator");
    // Instruct HTMX to redirect the browser to the protected dashboard
    res.setHeader("HX-Redirect", "/index");
    return res.status(200).send("Success");
  } catch (err) {
    // res.render("login", { error: "Login error" });
    return res.send(`
            <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg mb-4">
                Login processing error: ${err.message}
            </div>
        `);
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.redirect("/landing");
});

app.get("/generator", (req, res) => {
  res.render("generator");
});

// --- Endpoint A: Generate Token & Show Instructions ---
app.post("/api/market/generate-token", authMiddleware, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).send(`
                <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                    ❌ Please enter a valid domain (e.g., mysite.com).
                </div>
            `);
    }

    // Clean domain format
    const cleanDomain = domain
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .trim();

    // Generate 32-character secure random token
    const token = `faast_` + crypto.randomBytes(16).toString("hex");

    // Save to user session/db
    req.user.pendingDomain = cleanDomain;
    req.user.domainVerificationToken = token;
    await req.user.save();

    const metaTag = `<meta name="faast-verification" content="${token}">`;

    // Returns instruction card directly via HTMX
    return res.send(`
            <div class="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-4 text-xs text-slate-300">
                <p class="font-semibold text-white">Copy and paste this meta tag into the <code class="text-emerald-400">&lt;head&gt;</code> section of <span class="text-blue-400">${cleanDomain}</span>:</p>
                
                <div class="flex items-center justify-between bg-slate-900 p-2.5 rounded border border-slate-700 font-mono text-emerald-300">
                    <code>${metaTag}</code>
                </div>

                <p class="text-slate-400">Once added and published on your site, click below to verify.</p>

                <button 
                    hx-post="/api/market/verify-domain" 
                    hx-target="#verification-result" 
                    hx-swap="innerHTML"
                    class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded text-xs transition">
                    Verify Meta Tag
                </button>
            </div>
        `);
  } catch (err) {
    return res.status(500).send(`
            <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                ❌ Error generating verification token.
            </div>
        `);
  }
});

// --- Endpoint B: Verify Meta Tag on Remote Website ---
app.post(
  "/api/market/verify-domain",
  authMiddleware,
  checkDomainLimit,
  async (req, res) => {
    try {
      const domain = req.user.pendingDomain;
      const expectedToken = req.user.domainVerificationToken;

      if (!domain || !expectedToken) {
        return res.send(`
                <div class="bg-amber-900/40 border border-amber-600/60 text-amber-200 p-3 rounded-lg text-xs">
                    ⚠️ No pending domain verification found. Please generate a token first.
                </div>
            `);
      }

      // Fetch user's target website HTML (5-second timeout)
      let siteHtml = "";
      try {
        const targetUrl = domain.startsWith("http")
          ? domain
          : `https://${domain}`;
        const response = await axios.get(targetUrl, {
          timeout: 5000,
          headers: { "User-Agent": "FaastSaaS-DomainVerifier/1.0" },
        });
        siteHtml = response.data;
      } catch (fetchErr) {
        return res.send(`
                <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                    ❌ Could not reach <strong>${domain}</strong> over HTTPS. Ensure the site is published and accessible.
                </div>
            `);
      }

      // Regex check for: <meta name="faast-verification" content="TOKEN">
      const metaRegex = new RegExp(
        `<meta\\s+name=["']faast-verification["']\\s+content=["']${expectedToken}["']`,
        "i",
      );
      const isVerified = metaRegex.test(siteHtml);

      if (!isVerified) {
        return res.send(`
                <div class="bg-amber-900/40 border border-amber-600/60 text-amber-200 p-3 rounded-lg text-xs">
                    ⚠️ Meta tag not detected on <strong>${domain}</strong>. If you just published changes, wait a minute for cache to clear and try again.
                </div>
            `);
      }

      // Success: Clear pending state and increment count
      req.user.verifiedDomainsCount = (req.user.verifiedDomainsCount || 0) + 1;
      req.user.pendingDomain = null;
      req.user.domainVerificationToken = null;
      await req.user.save();

      return res.send(`
            <div class="bg-emerald-900/40 border border-emerald-600/60 text-emerald-200 p-3 rounded-lg text-xs flex items-center justify-between">
                <span>✅ Domain <strong>${domain}</strong> successfully verified!</span>
                <span class="text-slate-400">Total Verified: ${req.user.verifiedDomainsCount}</span>
            </div>
        `);
    } catch (err) {
      return res.status(500).send(`
            <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                ❌ Verification failed due to a server error.
            </div>
        `);
    }
  },
);

app.post(
  "/api/market/analyze",
  authMiddleware,
  checkGenerationLimit,
  async (req, res) => {
    try {
      // 1. Support targetUrl, domain, or url form input names
      let rawUrl = req.body.targetUrl || req.body.domain || req.body.url;

      if (!rawUrl) {
        return res.send(`
          <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
            Analysis failed: Please provide a valid URL or domain.
          </div>
        `);
      }

      // 2. Automatically prepend https:// if missing
      let formattedUrl = rawUrl.trim();
      if (!/^https?:\/\//i.test(formattedUrl)) {
        formattedUrl = `https://${formattedUrl}`;
      }

      // 3. Generate strategy using the formatted URL & user context
      const strategyHtml = await generateMarketingStrategy(
        formattedUrl,
        req.user,
      );

      // 4. FIX: Increment generation/usage count (NOT verified domains count)
      req.user.saasGenerationsCount = (req.user.saasGenerationsCount || 0) + 1;
      await req.user.save();

      return res.send(strategyHtml);
    } catch (err) {
      // Inline verification prompt if domain ownership check fails inside generateMarketingStrategy
      if (err.message === "DOMAIN_UNAUTHORIZED") {
        return res.send(`
          <div class="bg-amber-900/40 border border-amber-600/50 p-6 rounded-xl text-amber-200">
            <h3 class="font-bold text-lg mb-2 flex items-center gap-2">⚠️ Ownership Verification Required</h3>
            <p class="text-sm mb-4">
              To crawl and analyze <code class="bg-slate-900 px-2 py-1 rounded text-white">${err.domainHost || "this domain"}</code>, 
              please verify ownership by adding this tag into your site's <code class="text-cyan-300">&lt;head&gt;</code> section:
            </p>
            <div class="bg-slate-950 p-3 rounded font-mono text-xs text-emerald-400 select-all overflow-x-auto mb-4">
              ${(err.metaRequired || "").replace(/</g, "&lt;").replace(/>/g, "&gt;")}
            </div>
            <p class="text-xs text-amber-300/80">
              Once added to your site's HTML, re-run the scan. Verified domains will automatically bypass this step on future scans.
            </p>
          </div>
        `);
      }

      return res.send(`
        <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
          Analysis failed: ${err.message}
        </div>
      `);
    }
  },
);

//=====================

app.listen(PORT, () =>
  console.log(
    `🔥 FaastSaaS compiler is now operational on http://localhost:${PORT}..`,
  ),
);
