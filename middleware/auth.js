const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET;

async function authMiddleware(req, res, next) {
  const token = req.cookies.auth_token;

  if (!token) {
    if (req.headers["hx-request"]) {
      res.setHeader("HX-Redirect", "/login");
      return res.status(401).send("Unauthorized");
    }
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.userId);
    if (!user) {
      res.clearCookie("auth_token");
      return res.redirect("/login");
    }

    await user.resetMonthlyQuotasIfNeeded();

    req.user = user;
    res.locals.user = user; // Accessible in EJS views
    next();
  } catch (err) {
    res.clearCookie("auth_token");
    if (req.headers["hx-request"]) {
      res.setHeader("HX-Redirect", "/login");
      return res.status(401).send("Unauthorized");
    }
    return res.redirect("/login");
  }
}

module.exports = { authMiddleware, JWT_SECRET };
