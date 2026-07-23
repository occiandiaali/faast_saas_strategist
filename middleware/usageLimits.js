// Guard for adding/verifying new domains
const checkDomainLimit = (req, res, next) => {
  const user = req.user; // Set by authMiddleware

  if (user.planTier === "free" && user.verifiedDomainsCount >= 1) {
    return res.send(`
            <div class="bg-amber-900/40 border border-amber-600/60 p-4 rounded-xl text-amber-200 text-sm mb-4">
                <div class="font-bold mb-1 flex items-center gap-2">
                    🔒 Free Tier Limit Reached
                </div>
                <p class="text-xs mb-3 text-amber-300/80">
                    You have reached your 1 verified domain limit. Upgrade to Pro for unlimited domain verifications and deep scans.
                </p>
                <a href="/pricing" class="inline-block bg-amber-400 hover:bg-amber-300 text-slate-950 text-xs font-bold px-3 py-1.5 rounded transition">
                    Upgrade to Pro →
                </a>
            </div>
        `);
  }
  next();
};

// Guard for generating SaaS marketing strategies
const checkGenerationLimit = (req, res, next) => {
  const user = req.user;

  if (user.planTier === "free" && user.saasGenerationsCount >= 1) {
    return res.send(`
            <div class="bg-amber-900/40 border border-amber-600/60 p-4 rounded-xl text-amber-200 text-sm mb-4">
                <div class="font-bold mb-1 flex items-center gap-2">
                    🔒 Free Tier Limit Reached
                </div>
                <p class="text-xs mb-3 text-amber-300/80">
                    You've used your 1 free SaaS project strategy generation. Upgrade to unlock unlimited AI strategy breakdowns.
                </p>
                <a href="/pricing" class="inline-block bg-amber-400 hover:bg-amber-300 text-slate-950 text-xs font-bold px-3 py-1.5 rounded transition">
                    Upgrade to Pro →
                </a>
            </div>
        `);
  }
  next();
};

module.exports = { checkDomainLimit, checkGenerationLimit };
