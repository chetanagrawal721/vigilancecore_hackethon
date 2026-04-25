/**
 * VigilanceCore AI Assistant — Frontend-only intelligence layer.
 * Multilingual Support Added (English, Hindi, Hinglish)
 */

/* eslint-disable no-unused-vars */
const VCAssistant = (() => {
  "use strict";

  const VULN_KB_EN = {
    ACCESS_CONTROL: {
      simple: "Anyone can call a function that should be restricted to the owner or admin.",
      why:    "An attacker could take over the contract, drain funds, or change critical settings.",
      risk:   "Very high — this is one of the most exploited vulnerability classes in real-world hacks.",
      next:   "Add an access modifier like `onlyOwner` or a `require(msg.sender == owner)` check at the top of the function.",
    },
    REENTRANCY: {
      simple: "The contract sends ETH before updating its own records, so an attacker can call back in and withdraw again before the balance is set to zero.",
      why:    "This is the exact pattern that caused the famous DAO hack in 2016, which lost $60 million worth of ETH.",
      risk:   "Critical — an attacker can repeatedly drain the contract's entire balance in a single transaction.",
      next:   "Follow the Checks-Effects-Interactions pattern: update the balance first, then send ETH.",
    },
    UNKNOWN: {
      simple: "The scanner detected a potential issue, but it doesn't fall into a common category.",
      why:    "Even uncommon issues can be exploited. The description and recommendation should give more context.",
      risk:   "Review the details carefully — the severity rating gives a good indication of impact.",
      next:   "Read the finding description and recommendation, then review the affected code manually.",
    },
  };

  const VULN_KB_HI = {
    ACCESS_CONTROL: {
      simple: "कोई भी व्यक्ति उस फ़ंक्शन को कॉल कर सकता है जो केवल ओनर या एडमिन के लिए होना चाहिए।",
      why:    "हमलावर कॉन्ट्रैक्ट पर कब्ज़ा कर सकता है, फंड निकाल सकता है, या महत्वपूर्ण सेटिंग्स बदल सकता है।",
      risk:   "बहुत अधिक — यह वास्तविक दुनिया के हैक्स में सबसे अधिक शोषित कमज़ोरियों में से एक है।",
      next:   "फ़ंक्शन के शीर्ष पर `onlyOwner` जैसा एक्सेस मॉडिफायर या `require(msg.sender == owner)` चेक जोड़ें।",
    },
    REENTRANCY: {
      simple: "कॉन्ट्रैक्ट अपने स्वयं के रिकॉर्ड को अपडेट करने से पहले ETH भेजता है, इसलिए एक हमलावर वापस कॉल कर सकता है और बैलेंस शून्य होने से पहले फिर से निकाल सकता है।",
      why:    "यह वही पैटर्न है जिसके कारण 2016 में प्रसिद्ध DAO हैक हुआ था, जिसमें 60 मिलियन डॉलर मूल्य का ETH खो गया था।",
      risk:   "गंभीर — एक हमलावर एक ही ट्रांजैक्शन में कॉन्ट्रैक्ट के पूरे बैलेंस को बार-बार निकाल सकता है।",
      next:   "चेक-इफेक्ट्स-इंटरेक्शन पैटर्न का पालन करें: पहले बैलेंस अपडेट करें, फिर ETH भेजें।",
    },
    UNKNOWN: {
      simple: "स्कैनर को एक संभावित समस्या का पता चला, लेकिन यह एक सामान्य श्रेणी में नहीं आता है।",
      why:    "असामान्य समस्याओं का भी फायदा उठाया जा सकता है। विवरण और अनुशंसा को अधिक संदर्भ देना चाहिए।",
      risk:   "विवरणों की सावधानीपूर्वक समीक्षा करें — गंभीरता रेटिंग प्रभाव का अच्छा संकेत देती है।",
      next:   "समस्या विवरण और अनुशंसा पढ़ें, फिर प्रभावित कोड की मैन्युअल रूप से समीक्षा करें।",
    },
  };

  const VULN_KB_HINGLISH = {
    ACCESS_CONTROL: {
      simple: "Koi bhi us function ko call kar sakta hai jo sirf owner ya admin ke liye hona chahiye.",
      why:    "Attacker contract par control le sakta hai, funds nikal sakta hai, ya critical settings change kar sakta hai.",
      risk:   "Bahut high — real-world hacks mein ye sabse zyada exploit hone wali vulnerability hai.",
      next:   "Function ke top par `onlyOwner` jaisa access modifier ya `require(msg.sender == owner)` check add karein.",
    },
    REENTRANCY: {
      simple: "Contract apne records update karne se pehle ETH send karta hai, isliye attacker wapas call kar sakta hai aur balance zero hone se pehle fir se withdraw kar sakta hai.",
      why:    "Ye wahi pattern hai jiski wajah se 2016 mein famous DAO hack hua tha, jisme $60 million worth ka ETH loss hua tha.",
      risk:   "Critical — attacker single transaction mein contract ka poora balance baar-baar drain kar sakta hai.",
      next:   "Checks-Effects-Interactions pattern follow karein: pehle balance update karein, fir ETH send karein.",
    },
    UNKNOWN: {
      simple: "Scanner ko ek potential issue mila hai, lekin ye common category mein nahi aata.",
      why:    "Uncommon issues ko bhi exploit kiya jaa sakta hai. Description aur recommendation padhein.",
      risk:   "Details ko carefully review karein — severity rating impact ka accha idea deti hai.",
      next:   "Finding description aur recommendation padhein, aur code ko manually check karein.",
    },
  };

  const UI_STRINGS = {
    en: {
      noIssues: "✅ Good news! The scan completed and **no vulnerabilities were detected**.\n\nRecommended next steps:\n• Manual audit\n• Unit tests",
      summaryTitle: "📋 **Scan Summary**\n\n",
      foundIssues: (n, fn) => `The analysis found **${n} issue${n > 1 ? "s" : ""}**.\n\n`,
      highestSev: (sev) => `\nThe highest severity found is **${sev}**. `,
      safeToDeployNo: "⚠️ **No, this contract is NOT safe to deploy.**",
      safeToDeployYes: "The scan found some issues, but none are critical. You should still review and fix them.",
      fallback: "I'm here to help! You can ask:\n• \"Give me a summary\"\n• \"Explain finding 1\"\n• \"Is this safe to deploy?\""
    },
    hi: {
      noIssues: "✅ खुशखबरी! स्कैन पूरा हो गया और **कोई कमज़ोरी नहीं मिली**।\n\nसुझाए गए अगले कदम:\n• मैन्युअल ऑडिट\n• यूनिट परीक्षण",
      summaryTitle: "📋 **स्कैन सारांश**\n\n",
      foundIssues: (n, fn) => `विश्लेषण में **${n} समस्याएँ** मिलीं।\n\n`,
      highestSev: (sev) => `\nमिली सबसे अधिक गंभीरता **${sev}** है। `,
      safeToDeployNo: "⚠️ **नहीं, यह कॉन्ट्रैक्ट डिप्लॉय करने के लिए सुरक्षित नहीं है।**",
      safeToDeployYes: "स्कैन में कुछ समस्याएँ मिलीं, लेकिन कोई गंभीर नहीं है। आपको फिर भी उनकी समीक्षा और समाधान करना चाहिए।",
      fallback: "मैं यहाँ मदद करने के लिए हूँ! आप पूछ सकते हैं:\n• \"मुझे सारांश दें\"\n• \"समस्या 1 समझाएं\"\n• \"क्या यह डिप्लॉय करने के लिए सुरक्षित है?\""
    },
    hinglish: {
      noIssues: "✅ Good news! Scan complete ho gaya aur **koi vulnerability nahi mili**.\n\nNext steps:\n• Manual audit\n• Unit tests",
      summaryTitle: "📋 **Scan Summary**\n\n",
      foundIssues: (n, fn) => `Analysis mein **${n} issues** mile hain.\n\n`,
      highestSev: (sev) => `\nHighest severity **${sev}** hai. `,
      safeToDeployNo: "⚠️ **Nahi, yeh contract deploy karne ke liye safe NAHI hai.**",
      safeToDeployYes: "Scan mein kuch issues mile hain, par koi critical nahi hai. Fir bhi unhe fix karna zaroori hai.",
      fallback: "Main yahan help karne ke liye hoon! Aap pooch sakte hain:\n• \"Summary batao\"\n• \"Finding 1 explain karo\"\n• \"Kya yeh safe hai?\""
    }
  };

  function cleanType(raw) {
    return String(raw || "UNKNOWN").replace("VulnerabilityType.", "").trim();
  }

  function cleanSev(raw) {
    return String(raw || "informational").replace("Severity.", "").toLowerCase().trim();
  }

  function extractFilename(p) {
    return p ? p.split(/[\\/]/).pop() : "Unknown file";
  }

  function getKB(vulnType, lang = "en") {
    const key = cleanType(vulnType).toUpperCase().replace(/\s+/g, "_");
    const kbs = { en: VULN_KB_EN, hi: VULN_KB_HI, hinglish: VULN_KB_HINGLISH };
    const kb = kbs[lang] || kbs["en"];
    return kb[key] || kb.UNKNOWN;
  }

  function sevEmoji(sev) {
    const s = cleanSev(sev);
    if (s === "critical") return "🔴";
    if (s === "high")     return "🟠";
    if (s === "medium")   return "🟡";
    if (s === "low")      return "🔵";
    return "⚪";
  }

  function sevLabel(sev) {
    const s = cleanSev(sev);
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  class VCAssistant {
    constructor(reportData) {
      this.data     = reportData || {};
      this.findings = reportData?.findings || [];
      this.file     = extractFilename(reportData?.source_file);
      this.stats    = reportData?.stats || {};
    }

    summary(lang = "en") {
      const f  = this.findings;
      const n  = f.length;
      const strings = UI_STRINGS[lang] || UI_STRINGS["en"];

      if (n === 0) return strings.noIssues;

      const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
      f.forEach(fd => { const s = cleanSev(fd.severity); if (s in counts) counts[s]++; });

      const highest = ["critical","high","medium","low","informational"].find(s => counts[s] > 0) || "informational";

      let summary = strings.summaryTitle + strings.foundIssues(n, this.file);
      if (counts.critical) summary += `• 🔴 Critical: ${counts.critical}\n`;
      if (counts.high)     summary += `• 🟠 High: ${counts.high}\n`;
      if (counts.medium)   summary += `• 🟡 Medium: ${counts.medium}\n`;
      if (counts.low)      summary += `• 🔵 Low: ${counts.low}\n`;

      summary += strings.highestSev(sevLabel(highest));

      if (highest === "critical" || highest === "high") {
        summary += strings.safeToDeployNo;
      } else {
        summary += strings.safeToDeployYes;
      }
      return summary;
    }

    explainFinding(index, lang = "en") {
      const f = this.findings[index];
      if (!f) return lang === "hi" ? "❓ मुझे वह समस्या नहीं मिली।" : (lang === "hinglish" ? "❓ Mujhe wo finding nahi mili." : "❓ I couldn't find that finding.");

      const kb  = getKB(f.vuln_type, lang);
      const sev = sevLabel(f.severity);
      const em  = sevEmoji(f.severity);

      let text = `${em} **Finding #${index + 1}: ${f.title || "Unnamed Finding"}**\n\n`;
      text += `**Explanation:**\n${kb.simple}\n\n`;
      text += `**Why dangerous:**\n${kb.why}\n\n`;
      text += `**Risk:**\n${kb.risk}\n\n`;
      text += `**Fix:**\n${kb.next}\n`;

      return text;
    }

    ask(question, lang = "en") {
      let q = question.toLowerCase().trim();
      
      // Convert Hindi numerals to English numerals
      const hindiNumMap = {'०':'0','१':'1','२':'2','३':'3','४':'4','५':'5','६':'6','७':'7','८':'8','९':'9'};
      q = q.replace(/[०-९]/g, match => hindiNumMap[match]);

      const strings = UI_STRINGS[lang] || UI_STRINGS["en"];

      const findingMatch = q.match(/(?:finding|issue|vulnerability|samashya|समस्या|फाइंडिंग)\s*#?\s*(\d+)/);
      if (findingMatch) {
        const idx = parseInt(findingMatch[1], 10) - 1;
        return this.explainFinding(idx, lang);
      }

      if (q.includes("summary") || q.includes("saransh") || q.includes("overview") || q.includes("सारांश") || q.includes("समरी") || q.includes("जानकारी")) {
        return this.summary(lang);
      }

      if (q.includes("safe") || q.includes("deploy") || q.includes("surakshit") || q.includes("ready") || q.includes("सुरक्षित") || q.includes("डिप्लॉय") || q.includes("तैयार")) {
        const hasHigh = this.findings.some(fd => ["critical","high"].includes(cleanSev(fd.severity)));
        return hasHigh ? strings.safeToDeployNo : strings.safeToDeployYes;
      }

      return strings.fallback;
    }

    generateFullReport() {
      // Retaining original english report logic for downloads
      return "VigilanceCore AI Report\n\n" + this.summary("en"); 
    }
  }

  return VCAssistant;
})();
