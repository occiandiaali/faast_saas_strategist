require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { ZipArchive } = require("archiver");

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
                <span>✅ Domain <strong>${targetUrl}</strong> successfully verified! Copy & paste it in the field below.</span>
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
// Verified domains get crawled, and get Go-To-Market analyses
app.post("/api/analyze", authMiddleware, checkDomainLimit, async (req, res) => {
  try {
    const targetUrl = req.body?.url;

    if (!targetUrl) {
      return res.status(400).send(`
        <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
          Analysis failed: Missing 'url' parameter in request body.
        </div>
      `);
    }

    // Security check: Verify user owns or has verified this URL
    if (!req.user?.verifiedUrls?.includes(targetUrl)) {
      return res.status(403).send(`
        <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
          Analysis failed: You are not authorized to analyze this domain.
        </div>
      `);
    }

    // Generate strategy using formatted URL & user context
    const strategyHtml = await generateMarketingStrategy(targetUrl, req.user);
    //[TODO]: Add tracker to User model like req.user.gtmPlanRan, to check how many times
    // the user has scanned/generated a GTM plan for each verified domain under that account
    return res.status(200).send(strategyHtml);
  } catch (err) {
    console.error("Strategy Generation Error:", err);
    return res.status(500).send(`
        <div class="bg-red-900/40 border border-red-700/60 text-red-200 text-xs p-3 rounded-lg">
          Analysis failed: ${err.message}
        </div>
      `);
  }
});

//=== BOILERPLATE GENERATOR
app.post(
  "/api/generate",
  authMiddleware,
  checkGenerationLimit,
  async (req, res) => {
    try {
      const {
        appName = "MySaaSApp",
        paymentEngine = "stripe", // 'stripe' | 'lemonSqueezy'
        dbType = "mongodb", // 'mongodb' | 'supabase'
        mongoUrl = "",
        supabaseUrl = "",
        supabaseKey = "",
      } = req.body;

      const sanitizedAppName = appName.replace(/[^a-zA-Z0-9_-]/g, "");
      const isMongo = dbType === "mongodb";

      // Set response headers for zip download
      res.attachment(`${sanitizedAppName.toLowerCase()}-boilerplate.zip`);

      // Instantiate ZipArchive
      const archive = new ZipArchive({ zlib: { level: 9 } });
      archive.pipe(res);

      // ---------------------------------------------------------
      // 1. package.json (Minimal Dependencies)
      // ---------------------------------------------------------
      const packageJson = {
        name: sanitizedAppName.toLowerCase(),
        version: "0.0.1",
        description:
          "Minimal Express + EJS + HTMX + TailwindCSS SaaS Boilerplate",
        main: "server.js",
        scripts: {
          start: "node server.js",
          dev: "node --watch server.js",
        },
        dependencies: {
          express: "^5.2.1",
          dotenv: "^17.4.2",
          ejs: "^6.0.1",
          "cookie-parser": "^1.4.7",
          jsonwebtoken: "^9.0.3",

          ...(isMongo
            ? { mongoose: "^9.8.0", bcryptjs: "^3.0.3" }
            : { "@supabase/supabase-js": "^2.110.7" }),
          ...(paymentEngine === "stripe" ? { stripe: "^22.3.2" } : {}),
        },
      };
      archive.append(JSON.stringify(packageJson, null, 2), {
        name: "package.json",
      });

      // ---------------------------------------------------------
      // 2. .env Template
      // ---------------------------------------------------------
      const envContent = `
      PORT=3000
      JWT_SECRET=${Math.random().toString(36).substring(2)}${Date.now()}
      PAYMENT_ENGINE=${paymentEngine}
      STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key_here
      LEMONSQUEEZY_API_KEY=your_lemonsqueezy_api_key_here
      ${
        isMongo
          ? `MONGO_URI=${mongoUrl || "mongodb+srv://<username>:<password>@cluster.mongodb.net/mySaaS"}`
          : `SUPABASE_URL=${supabaseUrl || "https://your-project.supabase.co"}\nSUPABASE_KEY=${supabaseKey || "your-supabase-anon-key"}`
      }
    `;
      archive.append(envContent.trim(), { name: ".env" });
      const envContentExample = `
      JWT_SECRET=your_jsonwebtoken_secret
      PORT=the_running_server_port
      STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key_here
      LEMONSQUEEZY_API_KEY=your_lemonsqueezy_api_key_here
      PAYMENT_ENGINE=${paymentEngine}
      ${
        isMongo
          ? `MONGO_URI="mongodb+srv://<username>:<password>@cluster.mongodb.net/mySaaS"`
          : `SUPABASE_URL="https://your-project.supabase.co"\nSUPABASE_KEY="your-supabase-anon-or-service-key"`
      }
    `;

      archive.append(envContentExample.trim(), { name: ".env.example" });

      const gitIgnorance = `node_modules/\n.env\n.DS_Store\n*.log`;
      archive.append(gitIgnorance.trim(), { name: ".gitignore" });

      // ---------------------------------------------------------
      // 3. Database Module (config/db.js)
      // ---------------------------------------------------------
      const dbFileContent = isMongo
        ? `
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ MongoDB connected successfully.');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;
`
        : `
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

module.exports = supabase;
`;
      archive.append(dbFileContent.trim(), { name: "config/db.js" });

      // ---------------------------------------------------------
      // 4. User Model for MongoDB (models/User.js)
      // ---------------------------------------------------------
      if (isMongo) {
        const userModelContent = `
          const mongoose = require('mongoose');
          const bcrypt = require('bcryptjs');

          const userSchema = new mongoose.Schema({
            email: { type: String, required: true, unique: true, lowercase: true },
            password: { type: String, required: true },
            isSubscribed: { type: Boolean, default: false },
            customerId: String,
            subscriptionId: String,
            createdAt: { type: Date, default: Date.now }
          });

          userSchema.pre('save', async function () {
            if (!this.isModified('password')) return;
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
          });

          userSchema.methods.comparePassword = async function (candidatePassword) {
            return await bcrypt.compare(candidatePassword, this.password);
          };

          module.exports = mongoose.model('User', userSchema);
      `;
        archive.append(userModelContent.trim(), { name: "models/User.js" });
      }

      // ---------------------------------------------------------
      // 5. Main server.js Entry Point
      // ---------------------------------------------------------
      const serverJsContent = `
    require('dotenv').config();
    const express = require('express');
    const cookieParser = require('cookie-parser');
    const path = require('path');
    const jwt = require('jsonwebtoken');

    ${isMongo ? `const connectDB = require('./config/db.js');\nconst User = require('./models/User.js');` : `const supabase = require('./config/db.js');`}
    ${paymentEngine === "stripe" ? `const Stripe = require('stripe');\nconst stripe = Stripe(process.env.STRIPE_SECRET_KEY);` : ``}

    const app = express();

    ${isMongo ? `connectDB();` : ``}

    // Middleware
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(cookieParser());
    app.use(express.static(path.join(__dirname, 'public')));

    // EJS Setup
    app.set('view engine', 'html');
    app.engine('html', require('ejs').renderFile);
    app.set('views', path.join(__dirname, 'views'));

// JWT Auth Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    res.locals.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
};

// Global Template Vars
app.use((req, res, next) => {
  res.locals.appName = "${sanitizedAppName}";
  res.locals.paymentEngine = "${paymentEngine}";
  res.locals.user = null;
  
  if (req.cookies.token) {
    try {
      res.locals.user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
    } catch(e) {}
  }
  next();
});

// --- PAGE ROUTES ---
app.get('/', (req, res) => res.render('index.html'));
app.get('/about', (req, res) => res.render('about.html'));
app.get('/contact', (req, res) => res.render('contact.html'));
app.get('/login', (req, res) => res.render('login.html', { error: null }));
app.get('/signup', (req, res) => res.render('signup.html', { error: null }));
app.get('/dashboard', authMiddleware, (req, res) => res.render('dashboard.html'));

// --- AUTH API ROUTES ---
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    ${
      isMongo
        ? `
    let existing = await User.findOne({ email });
    if (existing) throw new Error("Email already registered.");
    const user = await User.create({ email, password });
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    `
        : `
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;
    const token = jwt.sign({ id: data.user.id, email: data.user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    `
    }
    res.cookie('token', token, { httpOnly: true, secure: false });
    return res.header('HX-Redirect', '/dashboard').send();
  } catch (err) {
    return res.send(\`<div class="bg-red-900/50 border border-red-500 text-red-200 text-xs p-3 rounded-lg mt-3">\${err.message}</div>\`);
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    ${
      isMongo
        ? `
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      throw new Error("Invalid email or password.");
    }
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    `
        : `
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    const token = jwt.sign({ id: data.user.id, email: data.user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    `
    }
    res.cookie('token', token, { httpOnly: true, secure: false });
    return res.header('HX-Redirect', '/dashboard').send();
  } catch (err) {
    return res.send(\`<div class="bg-red-900/50 border border-red-500 text-red-200 text-xs p-3 rounded-lg mt-3">\${err.message}</div>\`);
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// --- PAYMENTS ROUTE ---
app.post('/api/billing/checkout', authMiddleware, async (req, res) => {
  try {
    if (process.env.PAYMENT_ENGINE === 'stripe') {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: '${sanitizedAppName} Pro Plan' },
            unit_amount: 2900,
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: \`http://localhost:\${process.env.PORT || 3000}/dashboard?status=success\`,
        cancel_url: \`http://localhost:\${process.env.PORT || 3000}/dashboard?status=cancel\`,
      });
      return res.header('HX-Redirect', session.url).send();
    } else {
      // Lemon Squeezy / Alternative fallback implementation
      return res.send('<div class="text-amber-400 text-sm">Lemon Squeezy Checkout URL generation ready. Insert your store link.</div>');
    }
  } catch (err) {
    return res.send(\`<div class="text-red-400 text-xs mt-2">Payment Failed: \${err.message}</div>\`);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(\`⚡ ${sanitizedAppName} listening at http://localhost:\${PORT}\`));
`;
      archive.append(serverJsContent.trim(), { name: "server.js" });

      // ---------------------------------------------------------
      // 6. View Partials & Layout Pages
      // ---------------------------------------------------------
      const navPartial = `
<nav class="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
  <div class="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
    <a href="/" class="text-xl font-black text-emerald-400 flex items-center gap-2">
      <%= appName %>
    </a>
    <div class="flex items-center space-x-6 text-sm font-medium text-slate-300">
      <a href="/about" class="hover:text-emerald-400 transition">About</a>
      <a href="/contact" class="hover:text-emerald-400 transition">Contact</a>
      <% if (user) { %>
        <a href="/dashboard" class="text-emerald-400 font-semibold">Dashboard</a>
        <a href="/logout" class="bg-red-900/30 text-red-300 border border-red-700/50 px-3 py-1.5 rounded-lg hover:bg-red-900/50 transition">Logout</a>
      <% } else { %>
        <a href="/login" class="hover:text-white transition">Sign In</a>
        <a href="/signup" class="bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-4 py-2 rounded-lg font-bold transition">Get Started</a>
      <% } %>
    </div>
  </div>
</nav>
`;

      const footerPartial = `
<footer class="border-t border-slate-800 bg-slate-950 mt-auto py-10 text-slate-500 text-xs">
  <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-4">
    <div>&copy; <%= new Date().getFullYear() %> <%= appName %>. All rights reserved.</div>
    <div class="flex space-x-4">
      <a href="/about" class="hover:text-slate-300">About</a>
      <a href="/contact" class="hover:text-slate-300">Contact</a>
      <a href="#" class="hover:text-slate-300">Privacy Policy</a>
    </div>
  </div>
</footer>
`;

      const indexPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= appName %> | Build Faster</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col font-sans">
  <%- include('partials/nav.html') %>

  <!-- Hero Section -->
  <section class="py-24 max-w-5xl mx-auto text-center px-6 space-y-8">
    <div class="inline-block bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs px-3 py-1 rounded-full">
      Production-Ready SaaS Template
    </div>
    <h1 class="text-5xl md:text-6xl font-black text-white tracking-tight leading-tight">
      Launch Your SaaS Product in <span class="text-emerald-400">Record Time</span>
    </h1>
    <p class="text-slate-400 text-lg md:text-xl max-w-2xl mx-auto">
      Pre-configured authentication, database integration, subscription billing, and modern HTMX UI components out of the box.
    </p>
    <div class="flex justify-center gap-4 pt-4">
      <a href="/signup" class="bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-base px-8 py-3.5 rounded-xl font-bold shadow-lg shadow-emerald-500/20 transition">Start Free Trial</a>
      <a href="/about" class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-base px-8 py-3.5 rounded-xl font-semibold border border-slate-700 transition">Learn More</a>
    </div>
  </section>

  <!-- Pricing Section -->
  <section class="py-16 bg-slate-950/50 border-t border-slate-800">
    <div class="max-w-5xl mx-auto px-6">
      <h2 class="text-3xl font-bold text-center text-white mb-12">Simple, Transparent Pricing</h2>
      <div class="grid md:grid-cols-2 gap-8 max-w-3xl mx-auto">
        <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6">
          <h3 class="text-xl font-bold text-white">Starter</h3>
          <div class="text-4xl font-extrabold text-white">$9 <span class="text-sm font-normal text-slate-400">/mo</span></div>
          <ul class="text-slate-400 text-sm space-y-3">
            <li>✓ Essential Features</li>
            <li>✓ Up to 1,000 active users</li>
            <li>✓ Community Support</li>
          </ul>
          <a href="/signup" class="block text-center bg-slate-800 hover:bg-slate-700 text-white font-semibold py-3 rounded-xl border border-slate-700 transition">Get Started</a>
        </div>
        <div class="bg-slate-900 border-2 border-emerald-500 p-8 rounded-2xl space-y-6 relative">
          <span class="absolute -top-3 right-6 bg-emerald-500 text-slate-950 text-xs font-bold px-3 py-1 rounded-full uppercase">Most Popular</span>
          <h3 class="text-xl font-bold text-white">Pro Plan</h3>
          <div class="text-4xl font-extrabold text-white">$29 <span class="text-sm font-normal text-slate-400">/mo</span></div>
          <ul class="text-slate-400 text-sm space-y-3">
            <li>✓ All Starter Features</li>
            <li>✓ Unlimited Usage</li>
            <li>✓ Priority Email Support</li>
          </ul>
          <a href="/signup" class="block text-center bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold py-3 rounded-xl transition">Start Pro Trial</a>
        </div>
      </div>
    </div>
  </section>

  <%- include('partials/footer.html') %>
</body>
</html>
`;

      const dashboardPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><%= appName %> | Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col font-sans">
  <%- include('partials/nav.html') %>

  <div class="max-w-6xl mx-auto w-full px-6 py-10 space-y-8">
    <div class="flex justify-between items-center border-b border-slate-800 pb-6">
      <div>
        <h1 class="text-3xl font-bold text-white">User Dashboard</h1>
        <p class="text-slate-400 text-sm">Welcome back, <span class="text-emerald-400 font-mono"><%= user.email %></span></p>
      </div>
      <form hx-post="/api/billing/checkout" hx-swap="outerHTML">
        <button type="submit" class="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-5 py-2.5 rounded-lg shadow transition">
          Upgrade to Pro ($29)
        </button>
      </form>
    </div>

    <!-- Dummy Dashboard Content -->
    <div class="grid md:grid-cols-3 gap-6">
      <div class="bg-slate-800/50 border border-slate-700/60 p-6 rounded-xl">
        <div class="text-xs font-semibold text-slate-400 uppercase">Total API Calls</div>
        <div class="text-3xl font-extrabold text-white mt-2">12,480</div>
      </div>
      <div class="bg-slate-800/50 border border-slate-700/60 p-6 rounded-xl">
        <div class="text-xs font-semibold text-slate-400 uppercase">Subscription Status</div>
        <div class="text-xl font-bold text-emerald-400 mt-2">Active Free Tier</div>
      </div>
      <div class="bg-slate-800/50 border border-slate-700/60 p-6 rounded-xl">
        <div class="text-xs font-semibold text-slate-400 uppercase">Active Projects</div>
        <div class="text-3xl font-extrabold text-white mt-2">4</div>
      </div>
    </div>
  </div>

  <%- include('partials/footer.html') %>
</body>
</html>
`;

      const loginPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><%= appName %> | Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col justify-center items-center p-6">
  <div class="w-full max-w-md bg-slate-950 border border-slate-800 p-8 rounded-2xl shadow-2xl space-y-6">
    <div class="text-center">
      <a href="/" class="text-2xl font-black text-emerald-400"><%= appName %></a>
      <h2 class="text-xl font-bold text-white mt-4">Welcome Back</h2>
    </div>

    <form hx-post="/api/auth/login" hx-target="#auth-error" class="space-y-4">
      <div>
        <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Email Address</label>
        <input type="email" name="email" required class="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-emerald-500">
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Password</label>
        <input type="password" name="password" required class="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-emerald-500">
      </div>
      <div id="auth-error"></div>
      <button type="submit" class="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold p-3 rounded-lg transition">Sign In</button>
    </form>
    <p class="text-xs text-center text-slate-500">Don't have an account? <a href="/signup" class="text-emerald-400 hover:underline">Sign up</a></p>
  </div>
</body>
</html>
`;

      const signupPage = loginPage
        .replace("Welcome Back", "Create Your Account")
        .replace("/api/auth/login", "/api/auth/signup")
        .replace("Sign In", "Create Account")
        .replace(
          'Don\'t have an account? <a href="/signup" class="text-emerald-400 hover:underline">Sign up</a>',
          'Already have an account? <a href="/login" class="text-emerald-400 hover:underline">Sign in</a>',
        );

      const aboutPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><%= appName %> | About</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col">
  <%- include('partials/nav.html') %>
  <div class="max-w-4xl mx-auto py-16 px-6 space-y-6">
    <h1 class="text-4xl font-extrabold text-white">About <%= appName %></h1>
    <p class="text-slate-400 leading-relaxed">This application was bootstrapped using the FaastSaaS engine. It provides a flexible foundation built on Express, HTMX, and Tailwind CSS designed for rapid iteration.</p>
  </div>
  <%- include('partials/footer.html') %>
</body>
</html>
`;

      const contactPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><%= appName %> | Contact</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex flex-col">
  <%- include('partials/nav.html') %>
  <div class="max-w-xl mx-auto py-16 px-6 space-y-6 w-full">
    <h1 class="text-3xl font-extrabold text-white">Get in Touch</h1>
    <form class="space-y-4">
      <div>
        <label class="block text-xs font-semibold text-slate-400 mb-1">Name</label>
        <input type="text" class="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-sm text-white">
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-400 mb-1">Message</label>
        <textarea rows="4" class="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-sm text-white"></textarea>
      </div>
      <button type="button" class="bg-emerald-500 text-slate-950 font-bold px-6 py-3 rounded-lg">Send Message</button>
    </form>
  </div>
  <%- include('partials/footer.html') %>
</body>
</html>
`;

      // Append views and partials to ZIP
      archive.append(navPartial.trim(), { name: "views/partials/nav.html" });
      archive.append(footerPartial.trim(), {
        name: "views/partials/footer.html",
      });
      archive.append(indexPage.trim(), { name: "views/index.html" });
      archive.append(dashboardPage.trim(), { name: "views/dashboard.html" });
      archive.append(loginPage.trim(), { name: "views/login.html" });
      archive.append(signupPage.trim(), { name: "views/signup.html" });
      archive.append(aboutPage.trim(), { name: "views/about.html" });
      archive.append(contactPage.trim(), { name: "views/contact.html" });

      // Finalize ZIP archive
      await archive.finalize();
      // 4. FIX: Increment generation/usage count (NOT verified domains count)
      req.user.saasGenerationsCount = (req.user.saasGenerationsCount || 0) + 1;
      await req.user.save();
    } catch (err) {
      console.error("Generator Error:", err);
      res.status(500).send("Failed to generate boilerplate code.");
    }
  },
);

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
