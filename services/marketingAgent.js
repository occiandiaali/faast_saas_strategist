const cheerio = require("cheerio");
const { ChatGoogleGenerativeAI } = require("@langchain/google-genai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { StringOutputParser } = require("@langchain/core/output_parsers");

async function fetchSinglePage(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FaastCrawler/1.0",
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) return null;
    const html = await response.text();
    const $ = cheerio.load(html);

    // Remove boilerplate elements
    $("script, style, nav, footer, svg, iframe, noscript").remove();

    return {
      url,
      title: $("title").text().trim() || "No title",
      metaDesc: $('meta[name="description"]').attr("content") || "",
      headings: $("h1, h2, h3")
        .map((_, el) => $(el).text().trim())
        .get()
        .join(" | "),
      bodyText: $("body").text().replace(/\s+/g, " ").trim().slice(0, 1500),
      // Collect valid internal links for crawling
      links: $("a[href]")
        .map((_, el) => $(el).attr("href"))
        .get(),
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return null; // Gracefully fail individual page fetches
  }
}

async function crawlSaaSWebsite(targetUrl, maxPages = 4) {
  const baseUrl = new URL(targetUrl);

  // 1. Fetch main landing page
  const mainPage = await fetchSinglePage(targetUrl);
  if (!mainPage) {
    throw new Error(`Could not reach target URL: ${targetUrl}`);
  }

  const visitedUrls = new Set([targetUrl, targetUrl + "/"]);
  const pagesToCrawl = [];

  // 2. Filter internal subpages (e.g., /about, /pricing, /features)
  for (const link of mainPage.links) {
    try {
      const resolvedUrl = new URL(link, targetUrl);

      // Ensure link stays within the same domain/origin
      if (
        resolvedUrl.origin === baseUrl.origin &&
        !visitedUrls.has(resolvedUrl.href) &&
        !resolvedUrl.pathname.match(/\.(png|jpg|jpeg|gif|pdf|css|js)$/i)
      ) {
        visitedUrls.add(resolvedUrl.href);
        pagesToCrawl.push(resolvedUrl.href);
      }
    } catch (e) {
      // Ignore invalid URLs
    }

    if (pagesToCrawl.length >= maxPages - 1) break;
  }

  // 3. Crawl subpages concurrently
  const subPagePromises = pagesToCrawl.map((url) => fetchSinglePage(url));
  const subPages = (await Promise.all(subPagePromises)).filter(Boolean);

  const allPages = [mainPage, ...subPages];

  // 4. Combine results into a structured prompt context for your Strategy Agent
  const combinedSummary = allPages
    .map(
      (page, idx) => `
--- PAGE ${idx + 1}: ${page.url} ---
Title: ${page.title}
Description: ${page.metaDesc}
Headings: ${page.headings}
Content Snippet: ${page.bodyText}
`,
    )
    .join("\n");

  return {
    pageCount: allPages.length,
    siteContext: combinedSummary.slice(0, 8000), // Cap token size to prevent AI hanging
  };
}

async function generateMarketingStrategy(targetUrl, user) {
  const apiKey = process.env.GOOGLE_API_KEY;
  if (!apiKey) throw new Error("GOOGLE_API_KEY missing");

  const scrapedData = await crawlSaaSWebsite(targetUrl);

  const model = new ChatGoogleGenerativeAI({
    model: "gemini-3.1-flash-lite",
    temperature: 0.4,
    apiKey: apiKey,
  });
  const isFreeTier = !user || user.planTier === "free";

  // Tailor instructions based on tier
  const tierInstructions = isFreeTier
    ? `NOTE: The user is on the FREE TIER. Provide a MINIMAL, condensed summary with only 1 concise bullet point per section. At the end, add a small CTA notice encouraging them to upgrade to Pro for deep-dive messaging angles and a full 4-week roadmap.`
    : `Provide a DETAILED, comprehensive marketing strategy with full 4-week execution steps, SEO or effective discoverability advice, and deep ICP breakdowns.`;

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
            <span>⚡ <strong>Free Tier Preview</strong> — Upgrade to Starter/Pro for deep-dive analysis & full execution roadmap.</span>
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
    title: scrapedData?.title || "",
    metaDesc: scrapedData?.metaDesc || "",
    headings: scrapedData?.headings || "",
    bodyText: scrapedData?.bodyText || "",
    isFreeTier,
  });
}

module.exports = { generateMarketingStrategy };
