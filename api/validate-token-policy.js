import https from "https";
import geoiplite from "geoip-lite";
import dotenv from "dotenv";

dotenv.config();

const PORT = 3000;
const BLOCKED_COUNTRIES = ["KP", "IR", "RU", "SY", "CN"];
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check";

const EXPIRY_WORKING_HOURS = 900; // 15 minutes
const EXPIRY_NON_WORKING_HOURS = 300; // 5 minutes

function getClientIp(req) {
    try {
        const headers = req.body?.event?.request?.additionalHeaders || [];
        const ipHeader = headers.find((h) => h.name.toLowerCase() === "x-client-source-ip");
        return ipHeader?.value?.[0] || null;
    } catch (e) {
        console.warn("Failed to parse client IP:", e.message);
        return null;
    }
}

function lookupCountry(ip) {
    const geo = geoiplite.lookup(ip);
    return geo?.country || "UNKNOWN";
}

function callAbuseIPDB(ip) {
    const url = `${ABUSEIPDB_ENDPOINT}?ipAddress=${ip}`;
    const options = {
        method: "GET",
        headers: {
            Key: ABUSEIPDB_API_KEY,
            Accept: "application/json"
        }
    };

    return new Promise((resolve, reject) => {
        const req = https.request(url, options, (res) => {
            let data = "";
            res.on("data", (chunk) => data += chunk);
            res.on("end", () => {
                try {
                    const parsed = JSON.parse(data);
                    const score = parsed?.data?.abuseConfidenceScore ?? 0;
                    resolve(score);
                } catch (err) {
                    reject(new Error("Failed to parse AbuseIPDB response"));
                }
            });
        });

        req.on("error", (err) => {
            reject(err);
        });

        req.end();
    });
}

function isWorkingHours() {
    const hourUTC = new Date().getUTCHours();
    return (hourUTC >= 9 && hourUTC < 17); // 9 AM - 5 PM UTC
}

function denyResponse(reason) {
    return {
        actionStatus: "FAILED",
        failureReason: "access_denied",
        failureDescription: reason
    };
}

function allowResponse() {
    return {actionStatus: "SUCCESS"};
}

// Main route
module.exports = async (req, res) => {
    console.log("Received request:", JSON.stringify(req.body, null, 2));

    const ip = getClientIp(req);
    if (!ip) {
        console.warn("No IP address found. Denying by default.");
        return res.json(denyResponse("Unable to determine client IP."));
    }

    console.log(`Client IP: ${ip}`);

    const country = lookupCountry(ip);
    console.log(`Resolved country: ${country}`);

    if (BLOCKED_COUNTRIES.includes(country)) {
        console.log(`Blocked due to restricted country: ${country}`);
        return res.json(denyResponse(`Access token issuance is blocked from your region (${country}).`));
    }

    try {
        const abuseScore = await callAbuseIPDB(ip);
        console.log(`Abuse Confidence Score: ${abuseScore}`);

        if (abuseScore > 75) {
            console.log(`Blocked due to high abuse score.`);
            return res.json(denyResponse("Access token issuance is blocked due to high IP risk."));
        }

        if (abuseScore < 25) {
            console.log("Low abuse score. Allowing.");
            return res.json(allowResponse());
        }

        const expiry = isWorkingHours() ? EXPIRY_WORKING_HOURS : EXPIRY_NON_WORKING_HOURS;
        console.log(`Allowing with expiry ${expiry} seconds`);

        return res.json({
            actionStatus: "SUCCESS",
            operations: [
                {
                    op: "replace",
                    path: "/accessToken/claims/expires_in",
                    value: expiry.toString()
                }
            ]
        });
    } catch (err) {
        console.error("Error during AbuseIPDB lookup:", err.message);
        return res.json(denyResponse("Error checking IP reputation."));
    }
};
