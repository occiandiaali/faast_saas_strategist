const cheerio = require("cheerio");
const { ChatGoogleGenerativeAI } = require("@langchain/google-genai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { StringOutputParser } = require("@langchain/core/output_parsers");

/**
 * Fetch and extract text content + verify domain authorization token
 */
async function crawlSaaSWebsite(targetUrl, user) {
  const parsedUrl = new URL(targetUrl);
  const domainHost = parsedUrl.origin.toLowerCase();

  // 1. Check if user already verified this domain previously
  const isAlreadyVerified = user.verifiedUrls.some(
    (u) => u.toLowerCase() === domainHost,
  );

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const response = await fetch(targetUrl, {
    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
    signal: controller.signal,
  });
  clearTimeout(timeoutId);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const html = await response.text();
  const $ = cheerio.load(html);

  // Check meta verification token if domain isn't already saved
  if (!isAlreadyVerified) {
    const foundToken = $('meta[name="faastsaas-verification"]').attr("content");

    if (foundToken !== user.verificationToken) {
      const verificationError = new Error("DOMAIN_UNAUTHORIZED");
      verificationError.metaRequired = `<meta name="faastsaas-verification" content="${user.verificationToken}">`;
      verificationError.domainHost = domainHost;
      throw verificationError;
    }

    // Token found! Save to verified list
    user.verifiedUrls.push(domainHost);
    await user.save();
  }

  $("script, style, nav, footer, svg, iframe").remove();

  return {
    title: $("title").text().trim() || "No title",
    metaDesc: $('meta[name="description"]').attr("content") || "No description",
    headings: $("h1, h2, h3")
      .map((_, el) => $(el).text().trim())
      .get()
      .join(" | "),
    bodyText: $("body").text().replace(/\s+/g, " ").trim().slice(0, 3000),
  };
}

async function generateMarketingStrategy(targetUrl, user) {
  const apiKey = process.env.GOOGLE_API_KEY;
  if (!apiKey) throw new Error("GOOGLE_API_KEY missing");

  const scrapedData = await crawlSaaSWebsite(targetUrl, user);

  const model = new ChatGoogleGenerativeAI({
    model: "gemini-3.1-flash-lite",
    temperature: 0.4,
    apiKey: apiKey,
  });
  const isFreeTier = !user || user.planTier === "free";

  // Tailor instructions based on tier
  const tierInstructions = isFreeTier
    ? `NOTE: The user is on the FREE TIER. Provide a MINIMAL, condensed summary with only 1 concise bullet point per section. At the end, add a small CTA notice encouraging them to upgrade to Pro for deep-dive messaging angles and a full 4-week roadmap.`
    : `Provide a DETAILED, comprehensive marketing strategy with full 4-week execution steps and deep ICP breakdowns.`;

  const prompt = `
You are an expert SaaS Growth Lead and Marketing Strategist.
Analyze the target URL: ${targetUrl} and generate an actionable marketing strategy for the analyzed site.

${tierInstructions}

     TARGET URL: {targetUrl}
     PAGE TITLE: {title}
     META DESCRIPTION: {metaDesc}
     HEADINGS: {headings}
     BODY CONTENT: {bodyText}

FORMAT YOUR RESPONSE AS HTML (using Tailwind classes, no html/body wrapper):

<div id="marketing-strategy-content" class="space-y-6">
    ${
      isFreeTier
        ? `
        <div class="bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs p-3 rounded-lg flex items-center justify-between">
            <span>⚡ <strong>Free Tier Preview</strong> — Upgrade to Pro for deep-dive analysis & full execution roadmap.</span>
            <a href="/pricing" class="bg-emerald-400 text-slate-950 px-2 py-1 rounded font-bold hover:bg-emerald-300 transition">Upgrade</a>
        </div>
    `
        : ""
    }

    <section class="bg-slate-800/60 p-5 rounded-lg border border-slate-700">
        <h3 class="text-lg font-bold text-emerald-400 mb-2">🎯 Positioning & ICP</h3>
        <p class="text-slate-300 text-sm mb-2"><strong>Core Value Prop:</strong> Summarize what this SaaS does.</p>
        <p class="text-slate-300 text-sm"><strong>Ideal Customer Persona (ICP):</strong> Describe who needs this most.</p>
    </section>

    <section class="bg-slate-800/60 p-5 rounded-lg border border-slate-700">
        <h3 class="text-lg font-bold text-cyan-400 mb-3">🪝 Messaging Angles</h3>
        <ul class="list-disc list-inside space-y-2 text-slate-300 text-sm">
            <li><strong>Angle 1:</strong> ...</li>
            ${
              !isFreeTier
                ? `
     
                <li><strong>Angle 2 (Pain-focused):</strong> ...</li>
                 <li><strong>Angle 3 (Outcome-focused):</strong> ...</li>
                 <li><strong>Angle 4 (Speed/Efficiency-focused):</strong> ...</li>
            `
                : ""
            }
        </ul>
    </section>

    <section class="bg-slate-800/60 p-5 rounded-lg border border-slate-700">
        <h3 class="text-lg font-bold text-amber-400 mb-3">🚀 Go-To-Market Summary</h3>
        <div class="space-y-3 text-slate-300 text-sm">
            <div><strong class="text-white">Focus Action:</strong> Key strategy recommendation.</div>
            ${
              !isFreeTier
                ? `
              <div><strong class="text-white">Week 1: Foundations & Cold Outreach:</strong> Initial setup and outreach steps.</div>
                 <div><strong class="text-white">Week 2: Content & Social Channels:</strong> Platform strategies (LinkedIn, X, Reddit).</div>
                 <div><strong class="text-white">Week 3: Community & Launch Platforms:</strong> Product Hunt, directories, or relevant communities.</div>
                 <div><strong class="text-white">Week 4: Product-Led Growth (PLG):</strong> Onboarding polish, referral hooks, and feedback loops.</div>
              `
                : ""
            }
        </div>
    </section>
</div>
`;

  const chain = PromptTemplate.fromTemplate(prompt)
    .pipe(model)
    .pipe(new StringOutputParser());

  return await chain.invoke({
    targetUrl,
    title: scrapedData.title,
    metaDesc: scrapedData.metaDesc,
    headings: scrapedData.headings,
    bodyText: scrapedData.bodyText,
  });
}

module.exports = { generateMarketingStrategy };
