
"use strict";

const $ = id => document.getElementById(id);

const passwordInput = $("passwordInput");
const codeEditor = $("codeEditor");
const fileInput = $("fileInput");

let currentFileName = "pasted-code.txt";
let currentFindings = [];
let hasCompletedScan = false;
let scanSourceName = "";
let scanTime = null;

// ---------------- PASSWORD CHECKER ----------------

function checkPassword() {
    const password = passwordInput.value;

    const rules = {
        length: password.length >= 12,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    let score = Object.values(rules).filter(Boolean).length;

    // This score reflects only the five displayed requirements.
    const label = !password ? "Not checked"
        : score <= 2 ? "Weak"
        : score <= 4 ? "Moderate"
        : "Strong";

    $("strengthLabel").textContent = label;
    $("strengthScore").textContent = `${score}/5`;
    $("strengthBar").style.width = `${score * 20}%`;

    const colors = {
        "Not checked": "#4c9aff",
        "Weak": "#ff687b",
        "Moderate": "#f5bd58",
        "Strong": "#40d7a0"
    };

    $("strengthBar").style.background = colors[label];

    for (const [key, passed] of Object.entries(rules)) {
        const item = document.querySelector(`[data-rule="${key}"]`);

        item.classList.toggle("passed", Boolean(password) && passed);

        const original = {
            length: "At least 12 characters",
            upper: "An uppercase letter",
            lower: "A lowercase letter",
            number: "A number",
            symbol: "A special character"
        };

        item.textContent =
            `${passed && password ? "✓" : "○"} ${original[key]}`;
    }
}

passwordInput.addEventListener("input", checkPassword);

$("togglePassword").addEventListener("click", () => {
    const showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    $("togglePassword").textContent = showing ? "Show" : "Hide";
});

// Never place password contents in reports, logs, or scan results.

// ---------------- SOURCE FILE HANDLING ----------------

codeEditor.addEventListener("input", () => {
    $("lineCount").textContent =
        `${codeEditor.value ? codeEditor.value.split("\n").length : 0} lines`;
});

fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];

    if (!file) return;

    const allowedExtensions =
        /\.(py|js|jsx|ts|tsx|java|php|html|htm|sql|txt|c|cpp|cs|go|rb|xml|sh)$/i;

    if (!allowedExtensions.test(file.name)) {
        $("scanStatus").textContent = "Unsupported file type.";
        fileInput.value = "";
        return;
    }

    // Limit memory use when reading a local file.
    if (file.size > 1024 * 1024) {
        $("scanStatus").textContent =
            "File is larger than the 1 MB limit.";
        fileInput.value = "";
        return;
    }

    try {
        $("scanStatus").textContent = "Reading local file...";

        const content = await file.text();

        // Treat uploaded content strictly as text.
        codeEditor.value = content;
        currentFileName = file.name;
        $("fileName").textContent =
            `${file.name} (${file.size.toLocaleString()} bytes)`;

        $("lineCount").textContent =
            `${content ? content.split("\n").length : 0} lines`;

        $("scanStatus").textContent =
            "File loaded locally. Ready to scan.";
    } catch {
        $("scanStatus").textContent = "Unable to read this file.";
    }
});

// ---------------- STATIC SECURITY RULES ----------------

// These rules find suspicious code patterns, not proven exploits.
// Matches can be false positives and need manual review.
const rules = [
    {
        id: "python-eval",
        severity: "High",
        issue: "Dynamic code execution with eval()",
        regex: /\beval\s*\(/g,
        languages: ["py", "js", "jsx", "ts", "tsx"],
        advice: "Avoid evaluating untrusted strings as code. Use safe parsing or explicit logic."
    },
    {
        id: "python-exec",
        severity: "High",
        issue: "Dynamic code execution with exec()",
        regex: /\bexec\s*\(/g,
        languages: ["py"],
        advice: "Avoid exec() with dynamic or untrusted content. Replace it with fixed, explicit operations."
    },
    {
        id: "shell-true",
        severity: "High",
        issue: "Shell execution enabled in subprocess",
        regex: /\bshell\s*=\s*True\b/g,
        languages: ["py"],
        advice: "Prefer subprocess argument lists with shell=False and validate external inputs."
    },
    {
        id: "hardcoded-secret",
        severity: "Critical",
        issue: "Possible hardcoded credential or secret",
        regex: /\b(?:password|passwd|api[_-]?key|secret|access[_-]?token)\b\s*[:=]\s*["'][^"'\r\n]{4,}["']/gi,
        languages: ["py", "js", "jsx", "ts", "tsx", "java", "php", "sql", "txt", "go", "rb", "sh"],
        advice: "Remove secrets from source code, rotate exposed credentials, and use a secret manager or environment variables."
    },
    {
        id: "sql-concat",
        severity: "High",
        issue: "Possible SQL query built with string concatenation",
        regex: /(?:execute|executemany|query)\s*\(\s*["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*(?:["'`]\s*\+|\$\{|%s)/gi,
        languages: ["py", "js", "jsx", "ts", "java", "php", "sql"],
        advice: "Use parameterized queries or prepared statements rather than concatenating untrusted values."
    },
    {
        id: "weak-hash",
        severity: "High",
        issue: "Use of a weak cryptographic hash",
        regex: /\b(?:md5|sha1)\s*\(/gi,
        languages: ["py", "js", "jsx", "ts", "java", "php"],
        advice: "For password storage, use a dedicated password-hashing algorithm such as Argon2id, scrypt, or bcrypt."
    },
    {
        id: "disabled-tls",
        severity: "High",
        issue: "TLS certificate verification may be disabled",
        regex: /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["'])/g,
        languages: ["py", "js", "jsx", "ts"],
        advice: "Enable certificate verification. Fix trust-store or certificate problems rather than disabling checks."
    },
    {
        id: "unsafe-html",
        severity: "Medium",
        issue: "Potentially unsafe HTML insertion",
        regex: /\.innerHTML\s*=/g,
        languages: ["js", "jsx", "ts"],
        advice: "Avoid inserting untrusted strings into HTML. Prefer textContent or use a well-maintained HTML sanitizer."
    },
    {
        id: "php-shell",
        severity: "High",
        issue: "Potential shell command execution",
        regex: /\b(?:shell_exec|system|passthru|popen)\s*\(/g,
        languages: ["php"],
        advice: "Avoid constructing shell commands from user input. Use safer APIs and strict input validation."
    },
    {
        id: "php-weak-random",
        severity: "Medium",
        issue: "Non-cryptographic random generator used",
        regex: /\b(?:rand|mt_rand)\s*\(/g,
        languages: ["php"],
        advice: "Use a cryptographically secure random source for tokens, reset links, and security-sensitive values."
    },
    {
        id: "js-document-write",
        severity: "Medium",
        issue: "Potentially unsafe document.write()",
        regex: /\bdocument\.write\s*\(/g,
        languages: ["js", "jsx", "ts"],
        advice: "Avoid writing untrusted content into the document. Use safe DOM methods."
    },
    {
        id: "debug-enabled",
        severity: "Low",
        issue: "Debug mode may be enabled",
        regex: /\bDEBUG\s*=\s*True\b/g,
        languages: ["py"],
        advice: "Ensure debug mode is disabled in production and avoid exposing detailed error messages."
    }
];

function getExtension(filename) {
    const match = filename.match(/\.([^.]+)$/);
    return match ? match[1].toLowerCase() : "txt";
}

// Basic comment filtering to reduce some false positives.
// This is intentionally conservative and is not a full language parser.
function removeSimpleComments(line, extension) {
    if (extension === "py" || extension === "rb" || extension === "sh") {
        return line.replace(/#.*$/, "");
    }

    if (extension === "html" || extension === "htm" ||
        extension === "xml") {
        return line.replace(/<!--.*?-->/g, "");
    }

    if (extension === "sql") {
        return line.replace(/--.*$/, "").replace(/#.*$/, "");
    }

    if (["js", "jsx", "ts", "tsx", "java", "c", "cpp", "cs", "go", "php"]
        .includes(extension)) {
        return line.replace(/\/\/.*$/, "");
    }

    return line;
}

function scanSource(source, filename) {
    const extension = getExtension(filename);
    const lines = source.split(/\r?\n/);
    const findings = [];

    lines.forEach((originalLine, index) => {
        const line = removeSimpleComments(originalLine, extension);

        for (const rule of rules) {
            if (!rule.languages.includes(extension)) continue;

            // Reset global regex state before testing each line.
            rule.regex.lastIndex = 0;

            if (rule.regex.test(line)) {
                findings.push({
                    severity: rule.severity,
                    issue: rule.issue,
                    file: filename,
                    line: index + 1,
                    remediation: rule.advice,
                    ruleId: rule.id
                });
            }
        }
    });

    return findings;
}

// ---------------- DASHBOARD AND RESULTS ----------------

function getCounts(findings) {
    return {
        Critical: findings.filter(f => f.severity === "Critical").length,
        High: findings.filter(f => f.severity === "High").length,
        Medium: findings.filter(f => f.severity === "Medium").length,
        Low: findings.filter(f => f.severity === "Low").length
    };
}

function calculateScore(findings) {
    // A transparent heuristic, not a certification or proof of security.
    const weights = {
        Critical: 25,
        High: 15,
        Medium: 7,
        Low: 3
    };

    const totalPenalty = findings.reduce(
        (sum, finding) => sum + weights[finding.severity], 0
    );

    return Math.max(0, 100 - totalPenalty);
}

function renderFindings(findings) {
    const body = $("findingsBody");
    body.replaceChildren();

    if (findings.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.className = "empty-state";
        cell.textContent =
            "No supported patterns matched. This does not prove the code is secure.";

        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    findings.forEach(finding => {
        const row = document.createElement("tr");

        const values = [
            finding.severity,
            finding.issue,
            finding.file,
            String(finding.line),
            finding.remediation
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");

            if (index === 0) {
                const badge = document.createElement("span");
                badge.className =
                    "severity " + finding.severity.toLowerCase();
                badge.textContent = finding.severity;
                cell.appendChild(badge);
            } else {
                cell.textContent = value;
            }

            row.appendChild(cell);
        });

        body.appendChild(row);
    });
}

function renderReport(findings, filename, timestamp, score) {
    const counts = getCounts(findings);
    const preview = $("reportPreview");
    preview.replaceChildren();

    const title = document.createElement("h3");
    title.textContent = "Static Analysis Report";
    preview.appendChild(title);

    const details = [
        `File: ${filename}`,
        `Scan date: ${timestamp.toLocaleString()}`,
        `Security score: ${score}/100 (heuristic)`,
        `Total pattern matches: ${findings.length}`,
        `Critical: ${counts.Critical} | High: ${counts.High} | Medium: ${counts.Medium} | Low: ${counts.Low}`,
        "Method: Local, pattern-based static analysis.",
        "Limitations: Results may contain false positives and do not establish that code is secure."
    ];

    details.forEach(text => {
        const p = document.createElement("p");
        p.textContent = text;
        preview.appendChild(p);
    });

    if (findings.length === 0) {
        const p = document.createElement("p");
        p.textContent = "No supported patterns matched in this scan.";
        preview.appendChild(p);
    } else {
        const list = document.createElement("ul");

        findings.forEach(finding => {
            const item = document.createElement("li");
            item.textContent =
                `${finding.severity}: ${finding.issue} — ${finding.file}:${finding.line}. ${finding.remediation}`;
            list.appendChild(item);
        });

        preview.appendChild(list);
    }
}

function updateDashboard(findings, filename, timestamp) {
    const counts = getCounts(findings);
    const score = calculateScore(findings);

    $("securityScore").innerHTML =
        `${score}<small>/100</small>`;

    $("scoreBar").style.width = `${score}%`;
    $("scoreNote").textContent =
        "Heuristic score based on matched patterns; not a security guarantee.";

    $("criticalCount").textContent = counts.Critical;
    $("highCount").textContent = counts.High;
    $("otherCount").textContent = counts.Medium + counts.Low;

    $("findingsSummary").textContent =
        `${findings.length} pattern match(es) in ${filename}.`;

    $("scanBadge").textContent = "Scan completed";

    renderFindings(findings);
    renderReport(findings, filename, timestamp, score);

    $("htmlExport").disabled = false;
    $("pdfExport").disabled = false;
}

function setEmptyDashboard() {
    $("securityScore").innerHTML = `—<small>/100</small>`;
    $("scoreBar").style.width = "0";
    $("scoreNote").textContent = "Run a code scan to calculate a score.";
    $("criticalCount").textContent = "0";
    $("highCount").textContent = "0";
    $("otherCount").textContent = "0";
    $("scanBadge").textContent = "Not scanned";
    $("findingsSummary").textContent = "No scan has been performed yet.";
    $("htmlExport").disabled = true;
    $("pdfExport").disabled = true;
}

// ---------------- SCAN BUTTON ----------------

$("scanButton").addEventListener("click", () => {
    const source = codeEditor.value;

    if (!source.trim()) {
        $("scanStatus").textContent =
            "Please upload a source file or paste code first.";
        return;
    }

    const filename = currentFileName || "pasted-code.txt";

    $("scanButton").disabled = true;
    $("scanStatus").textContent = "Scanning source patterns...";

    // No source is sent over the network and no code is executed.
    // Run the scan asynchronously so the loading status can render.
    setTimeout(() => {
        try {
            currentFindings = scanSource(source, filename);
            scanSourceName = filename;
            scanTime = new Date();
            hasCompletedScan = true;

            updateDashboard(currentFindings, scanSourceName, scanTime);

            $("scanStatus").textContent =
                `Scan completed. ${currentFindings.length} pattern match(es) found.`;
        } catch {
            $("scanStatus").textContent =
                "Scan failed. Check the input and try again.";
        } finally {
            $("scanButton").disabled = false;
        }
    }, 100);
});

$("clearButton").addEventListener("click", () => {
    codeEditor.value = "";
    fileInput.value = "";
    currentFileName = "pasted-code.txt";
    currentFindings = [];
    hasCompletedScan = false;
    scanSourceName = "";
    scanTime = null;

    $("fileName").textContent = "No file selected";
    $("lineCount").textContent = "0 lines";
    $("scanStatus").textContent = "Editor cleared. Ready to scan.";

    $("findingsBody").replaceChildren();

    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty-state";
    cell.textContent = "No results yet. Run a new scan.";
    row.appendChild(cell);
    $("findingsBody").appendChild(row);

    setEmptyDashboard();

    $("reportPreview").replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = "Report preview";
    const paragraph = document.createElement("p");
    paragraph.textContent = "No completed scan to report yet.";
    $("reportPreview").append(heading, paragraph);
});

// ---------------- REPORT EXPORTS ----------------

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

$("htmlExport").addEventListener("click", () => {
    if (!hasCompletedScan) return;

    const score = calculateScore(currentFindings);
    const counts = getCounts(currentFindings);

    const rows = currentFindings.map(f => `
        <tr>
            <td>${escapeHTML(f.severity)}</td>
            <td>${escapeHTML(f.issue)}</td>
            <td>${escapeHTML(f.file)}</td>
            <td>${f.line}</td>
            <td>${escapeHTML(f.remediation)}</td>
        </tr>
    `).join("");

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Static Analysis Report</title>
<style>
body{font:15px Arial,sans-serif;margin:30px;color:#172033}
h1{color:#174a7e}table{width:100%;border-collapse:collapse}
th,td{border:1px solid #ccd5e1;padding:10px;text-align:left}
th{background:#e8f1fb}p{line-height:1.6}
</style>
</head>
<body>
<h1>Secure Code Assessment Report</h1>
<p>File: ${escapeHTML(scanSourceName)}</p>
<p>Scan date: ${escapeHTML(scanTime.toLocaleString())}</p>
<p>Heuristic security score: ${score}/100</p>
<p>Pattern matches: ${currentFindings.length}</p>
<p>Critical: ${counts.Critical} | High: ${counts.High} |
Medium: ${counts.Medium} | Low: ${counts.Low}</p>
<p>This report is generated by a basic pattern-based scanner.
Matches may be false positives. No matches do not prove the code is secure.</p>
<table>
<thead><tr><th>Severity</th><th>Issue</th><th>File</th>
<th>Line</th><th>Remediation</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5">No supported patterns matched.</td></tr>'}</tbody>
</table>
</body></html>`;

    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "secure_code_assessment_report.html";
    link.click();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

$("pdfExport").addEventListener("click", () => {
    if (!hasCompletedScan) return;

    // Print the report area only. Choose "Save as PDF" in the print dialog.
    const reportWindow = window.open("", "_blank");

    if (!reportWindow) {
        $("scanStatus").textContent =
            "Print window blocked. Allow pop-ups for this local page and try again.";
        return;
    }

    const counts = getCounts(currentFindings);

    const rows = currentFindings.map(f => `
        <tr>
            <td>${escapeHTML(f.severity)}</td>
            <td>${escapeHTML(f.issue)}</td>
            <td>${escapeHTML(f.file)}</td>
            <td>${f.line}</td>
            <td>${escapeHTML(f.remediation)}</td>
        </tr>
    `).join("");

    reportWindow.document.write(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Security Report</title>
<style>
body{font:13px Arial,sans-serif;color:#172033;padding:20px}
h1{font-size:23px}table{width:100%;border-collapse:collapse}
th,td{border:1px solid #bbb;padding:7px;text-align:left;overflow-wrap:anywhere}
th{background:#edf2f7}p{line-height:1.5}
@media print{body{padding:0}tr{break-inside:avoid}}
</style></head><body>
<h1>Secure Code Assessment Report</h1>
<p>File: ${escapeHTML(scanSourceName)}</p>
<p>Scan date: ${escapeHTML(scanTime.toLocaleString())}</p>
<p>Heuristic security score: ${calculateScore(currentFindings)}/100</p>
<p>Pattern matches: ${currentFindings.length}</p>
<p>Critical: ${counts.Critical}, High: ${counts.High},
Medium: ${counts.Medium}, Low: ${counts.Low}</p>
<p>Basic pattern-based analysis only. False positives are possible.
No matches do not prove the code is secure.</p>
<table><thead><tr><th>Severity</th><th>Issue</th><th>File</th>
<th>Line</th><th>Remediation</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5">No supported patterns matched.</td></tr>'}</tbody>
</table></body></html>`);

    reportWindow.document.close();
    reportWindow.focus();
    reportWindow.onload = () => reportWindow.print();
});

// Initial empty state: no fake counts or invented findings.
checkPassword();
setEmptyDashboard();
