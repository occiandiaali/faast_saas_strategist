require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const archiver = require("archiver");
const crypto = require("crypto"); // For domain verification token generation
const https = require("https");
const http = require("http"); // For /api/generate-token and /api/verify-domain endpoints
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
const { generateMarketingStrategy } = require("./services/marketingAgent");

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

app.get("/index", authMiddleware, (req, res) => {
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
  res.redirect("/");
});

app.get("/generator", authMiddleware, (req, res) => {
  res.render("generator");
});

// --- Endpoint A: Generate Token & Show Instructions ---
app.post("/api/generate-token", authMiddleware, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).send(`
                <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                    ❌ Please enter a valid URL or domain (e.g., localhost:8080 or mysite.com).
                </div>
            `);
    }

    let rawInput = domain.trim();

    // Automatically prepend a scheme if missing so URL parser doesn't crash
    if (!/^https?:\/\//i.test(rawInput)) {
      const isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(rawInput);
      rawInput = isLocal ? `http://${rawInput}` : `https://${rawInput}`;
    }

    // Safely parse URL
    let parsedUrl;
    try {
      parsedUrl = new URL(rawInput);
    } catch (e) {
      return res.status(400).send(`
                <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                    ❌ Invalid URL format.
                </div>
            `);
    }

    // Construct targetUrl (e.g., "http://127.0.0.1:8080" or "https://mysite.com")
    const targetUrl = parsedUrl.origin;

    // Generate token
    const token = `faast_` + crypto.randomBytes(16).toString("hex");

    // Save targetUrl to database
    req.user.pendingDomain = targetUrl;
    req.user.domainVerificationToken = token;
    await req.user.save();

    const metaTag = `<meta name="faast-verification" content="${token}">`;

    return res.send(`
            <div class="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-4 text-xs text-slate-300">
                <p class="font-semibold text-white">Copy and paste this meta tag into the <code class="text-emerald-400">&lt;head&gt;</code> section of <span class="text-blue-400">${targetUrl}</span>:</p>
                
                <div class="flex items-center justify-between bg-slate-900 p-2.5 rounded border border-slate-700 font-mono text-emerald-300 select-all overflow-x-auto">
                    <code>${metaTag.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code>
                </div>

                <p class="text-slate-400">Once added to your site's HTML, click below to verify.</p>

                <button 
                    hx-post="/api/verify-domain" 
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

app.post(
  "/api/verify-domain",
  authMiddleware,
  checkDomainLimit,
  async (req, res) => {
    try {
      const targetUrl = req.user.pendingDomain; // Contains "http://127.0.0.1:8080" or "https://example.com"
      const expectedToken = req.user.domainVerificationToken;

      if (!targetUrl || !expectedToken) {
        return res.send(`
                <div class="bg-amber-900/40 border border-amber-600/60 text-amber-200 p-3 rounded-lg text-xs">
                    ⚠️ No pending domain verification found. Please generate a token first.
                </div>
            `);
      }

      let siteHtml = "";
      try {
        // Configure Axios agent to ignore self-signed SSL errors during local testing
        const httpAgent = new http.Agent({ keepAlive: true });
        const httpsAgent = new https.Agent({ rejectUnauthorized: false });

        const response = await axios.get(targetUrl, {
          timeout: 5000,
          httpAgent,
          httpsAgent,
          headers: { "User-Agent": "FaastSaaS-DomainVerifier/1.0" },
        });
        siteHtml = response.data;
      } catch (fetchErr) {
        return res.send(`
                <div class="bg-red-900/40 border border-red-600/60 text-red-200 p-3 rounded-lg text-xs">
                    ❌ Could not reach <strong>${targetUrl}</strong> (${fetchErr.message}). Ensure your local server or remote site is actively running.
                </div>
            `);
      }

      // Check for the meta tag in the fetched HTML
      const metaRegex = new RegExp(
        `<meta\\s+name=["']faast-verification["']\\s+content=["']${expectedToken}["']`,
        "i",
      );
      const isVerified = metaRegex.test(siteHtml);

      if (!isVerified) {
        return res.send(`
                <div class="bg-amber-900/40 border border-amber-600/60 text-amber-200 p-3 rounded-lg text-xs">
                    ⚠️ Meta tag not detected on <strong>${targetUrl}</strong>. Check your HTML <head> section and try again.
                </div>
            `);
      }

      // Success: Increment count and reset pending verification
      req.user.verifiedDomainsCount = (req.user.verifiedDomainsCount || 0) + 1;
      req.user.pendingDomain = null;
      req.user.domainVerificationToken = null;
      req.user.verifiedUrls.push(targetUrl);
      await req.user.save();

      return res.send(`
            <div class="bg-emerald-900/40 border border-emerald-600/60 text-emerald-200 p-3 rounded-lg text-xs flex items-center justify-between">
                <span>✅ Domain <strong>${targetUrl}</strong> successfully verified!</span>
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

//==================================

app.post(
  "/api/analyze",
  authMiddleware,
  checkGenerationLimit,
  async (req, res) => {
    try {
      // // 1. Support targetUrl, domain, or url form input names
      //const rawUrl = req.body.url;
      console.log(`req.body.url: ${req.body.url}`);

      if (req.user.verifiedUrls.includes(req.body.url)) {
        // 3. Generate strategy using the formatted URL & user context
        const strategyHtml = await generateMarketingStrategy(
          req.body.url,
          req.user,
        );

        // 4. FIX: Increment generation/usage count (NOT verified domains count)
        req.user.saasGenerationsCount =
          (req.user.saasGenerationsCount || 0) + 1;
        await req.user.save();

        return res.send(strategyHtml);
      }
    } catch (err) {
      return res.send(`
        <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
          Analysis failed: ${err.message}
        </div>
      `);
    }
  },
);
//=== BOILERPLATE GENERATOR
app.post("/api/generate", authMiddleware, async (req, res) => {
  try {
    const {
      appName = "MySaaSApp",
      paymentEngine = "stripe", // 'stripe' | 'lemonSqueezy' | 'paddle'
      dbType = "mongodb", // 'mongodb' | 'supabase'
      mongoUrl = "",
      supabaseUrl = "",
      supabaseKey = "",
    } = req.body;

    const sanitizedAppName = appName.replace(/[^a-zA-Z0-9_-]/g, "");
    const isMongo = dbType === "mongodb";

    // Prepare dynamic archive
    const archive = archiver("zip", { zlib: { level: 9 } });
    res.attachment(`${sanitizedAppName.toLowerCase()}-boilerplate.zip`);
    archive.pipe(res);

    // 1. package.json
    const packageJson = {
      name: sanitizedAppName.toLowerCase(),
      version: "1.0.0",
      description:
        "Generated Express NodeJS + EJS + HTMX + TailwindCSS SaaS Boilerplate",
      main: "server.js",
      scripts: {
        start: "node server.js",
        dev: "nodemon server.js",
      },
      dependencies: {
        express: "^4.19.2",
        ejs: "^3.1.10",
        dotenv: "^16.4.5",
        "express-session": "^1.18.0",
        bcryptjs: "^2.4.3",
        ...(isMongo
          ? { mongoose: "^8.3.0", "connect-mongo": "^5.1.0" }
          : { "@supabase/supabase-js": "^2.48.0" }),
      },
      devDependencies: {
        nodemon: "^3.1.0",
        tailwindcss: "^3.4.3",
      },
    };
    archive.append(JSON.stringify(packageJson, null, 2), {
      name: "package.json",
    });

    // 2. .env configuration template
    const envContent = `
PORT=3000
SESSION_SECRET=${Math.random().toString(36).substring(2)}${Date.now()}
PAYMENT_ENGINE=${paymentEngine}
${
  isMongo
    ? `MONGO_URI=${mongoUrl || "mongodb+srv://<username>:<password>@cluster.mongodb.net/mySaaS"}`
    : `SUPABASE_URL=${supabaseUrl || "https://your-project.supabase.co"}\nSUPABASE_KEY=${supabaseKey || "your-supabase-anon-or-service-key"}`
}
`;
    archive.append(envContent.trim(), { name: ".env" });

    // 3. Database & Auth Module (db.js / auth.js)
    let dbFileContent = "";
    if (isMongo) {
      dbFileContent = `
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Atlas connected successfully.');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;
`;
    } else {
      dbFileContent = `
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

module.exports = supabase;
`;
    }
    archive.append(dbFileContent.trim(), { name: "config/db.js" });

    // 4. Main server.js Entry Point
    const serverJsContent = `
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');

${isMongo ? `const connectDB = require('./config/db.js');\nconst MongoStore = require('connect-mongo');` : `const supabase = require('./config/db.js');`}

const app = express();

${isMongo ? `// Connect Database\nconnectDB();` : ``}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// EJS View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  ${isMongo ? `store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),` : ``}
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 Hours
}));

// Global Template Middleware
app.use((req, res, next) => {
  res.locals.appName = "${sanitizedAppName}";
  res.locals.paymentEngine = "${paymentEngine}";
  res.locals.user = req.session.user || null;
  next();
});

// Authentication Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

// --- ROUTES ---

// Landing Page
app.get('/', (req, res) => {
  res.render('index');
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Auth POST Handlers
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    ${
      isMongo
        ? `
    // MongoDB User Auth Logic
    // const user = await User.findOne({ email });
    `
        : `
    // Supabase Auth Logic
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    `
    }
    
    // Mock user session binding
    req.session.user = { email };
    return res.header('HX-Redirect', '/dashboard').send();
  } catch (err) {
    return res.send(\`<div class="text-red-500 text-xs mt-2">\${err.message || 'Invalid credentials'}</div>\`);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Protected Dashboard Page
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard');
});

// Protected Billing Hub Page
app.get('/billing', requireAuth, (req, res) => {
  res.render('billing');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(\`⚡ ${sanitizedAppName} running on http://localhost:\${PORT}\`));
`;
    archive.append(serverJsContent.trim(), { name: "server.js" });

    // 5. Views Setup (EJS Templates)
    const headerPartial = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= appName %></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col font-sans">
    <nav class="border-b border-slate-800 p-4 flex justify-between items-center max-w-6xl mx-auto w-full">
        <a href="/" class="text-xl font-bold text-emerald-400"><%= appName %></a>
        <div class="space-x-4 text-sm">
            <% if (user) { %>
                <a href="/dashboard" class="hover:text-emerald-400">Dashboard</a>
                <a href="/billing" class="hover:text-emerald-400">Billing (<%= paymentEngine %>)</a>
                <a href="/logout" class="bg-red-600/30 text-red-300 border border-red-500/50 px-3 py-1 rounded">Logout</a>
            <% } else { %>
                <a href="/login" class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded font-medium">Login</a>
            <% } %>
        </div>
    </nav>
    <main class="flex-1 max-w-6xl w-full mx-auto p-6">
`;
    const footerPartial = `
    </main>
    <footer class="border-t border-slate-800 p-6 text-center text-slate-500 text-xs">
        &copy; <%= new Date().getFullYear() %> <%= appName %>. All rights reserved. Powered by ${isMongo ? "MongoDB" : "Supabase"}.
    </footer>
</body>
</html>
`;
    const indexView = `<%- include('partials/header') %>
<div class="text-center py-20 space-y-6">
    <h1 class="text-5xl font-extrabold text-white">Welcome to <%= appName %></h1>
    <p class="text-slate-400 text-lg max-w-xl mx-auto">Build, scale, and iterate instantly with Express, HTMX, and TailwindCSS.</p>
    <a href="/dashboard" class="inline-block bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-6 py-3 rounded-lg shadow-lg">Go to App Dashboard &rarr;</a>
</div>
<%- include('partials/footer') %>`;

    const dashboardView = `<%- include('partials/header') %>
<div class="space-y-6">
    <div class="bg-slate-800/60 border border-slate-700 p-6 rounded-xl">
        <h2 class="text-2xl font-bold">App Dashboard</h2>
        <p class="text-slate-400 text-sm mt-1">Logged in as: <span class="text-emerald-400 font-mono"><%= user.email %></span></p>
    </div>
</div>
<%- include('partials/footer') %>`;

    archive.append(headerPartial.trim(), { name: "views/partials/header.ejs" });
    archive.append(footerPartial.trim(), { name: "views/partials/footer.ejs" });
    archive.append(indexView.trim(), { name: "views/index.ejs" });
    archive.append(dashboardView.trim(), { name: "views/dashboard.ejs" });

    await archive.finalize();
  } catch (err) {
    console.error("Generator Error:", err);
    res.status(500).send("Failed to generate boilerplate code.");
  }
});

//===========PAYMENTS?
app.post("/payments/checkout", authMiddleware, async (req, res) => {
  try {
    const { plan } = req.body; // e.g. 'starter' or 'pro'
    const priceId =
      plan === "starter"
        ? process.env.STRIPE_PRICE_STARTER_MONTHLY
        : process.env.STRIPE_PRICE_PRO_MONTHLY;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      mode: "subscription",
      customer_email: req.user.email,
      client_reference_id: req.user._id.toString(), // 👈 Crucial for webhooks
      metadata: {
        userId: req.user._id.toString(),
        targetPlan: plan || "starter",
      },
      success_url: `${req.protocol}://${req.get("host")}/payments/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get("host")}/pricing`,
    });

    // 303 Redirect for POST form submissions
    res.redirect(303, session.url);
  } catch (err) {
    console.error("Stripe Checkout Error:", err);
    res.status(500).send("Failed to initiate checkout.");
  }
});

app.get("/payments/success", authMiddleware, (req, res) => {
  // Webhook handled the database update asynchronously!
  // We just show a friendly thank-you page or redirect to dashboard.
  res.send(`
        <div style="font-family: sans-serif; text-align: center; padding: 3rem;">
            <h1>🎉 Subscription Confirmed!</h1>
            <p>Your plan has been set to <strong>${req.user.planTier.toUpperCase()}</strong>.</p>
            <a href="/generator" style="display: inline-block; background: #10b981; color: #fff; padding: 0.75rem 1.5rem; text-decoration: none; border-radius: 6px; margin-top: 1rem;">Generate a SaaS</a>
        </div>
    `);
});

//=====================
app.use((req, res) => {
  res.redirect("/");
});

app.listen(PORT, () =>
  console.log(
    `🔥 FaastSaaS compiler is now operational on http://localhost:${PORT}..`,
  ),
);
