import https from "https";
import geoip from "geoip-country";

const BLOCKED_COUNTRIES = ["KP", "IR", "RU", "SY", "CN"];
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check";

const EXPIRY_WORKING_HOURS = 900; // 15 minutes
const EXPIRY_NON_WORKING_HOURS = 300; // 5 minutes

function getClientIp(event) {
    try {
        const body = JSON.parse(event.body);
        const headers = body?.event?.request?.additionalHeaders || [];
        const ipHeader = headers.find((h) => h.name.toLowerCase() === "x-client-source-ip");
        return ipHeader?.value?.[0] || null;
    } catch (e) {
        console.warn("Failed to parse client IP:", e.message);
        return null;
    }
}

function lookupCountry(ip) {
    const geo = geoip.lookup(ip);
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

export const handler = async (event) => {
    console.log("Received event:", JSON.stringify(event, null, 2));

    const ip = getClientIp(event);
    if (!ip) {
        console.warn("No IP address found. Denying the request by default.");
        return denyResponse();
    }

    console.log(`Client IP: ${ip}`);

    const country = lookupCountry(ip);
    console.log(`Resolved country: ${country}`);

    if (BLOCKED_COUNTRIES.includes(country)) {
        console.log(`Blocked due to restricted country: ${country}`);
        return denyResponse(`Access token issuance is blocked from your region (${country}).`);
    }

    try {
        const abuseScore = await callAbuseIPDB(ip);
        console.log(`Abuse Confidence Score: ${abuseScore}`);

        if (abuseScore > 75) {
            console.log(`Blocked due to high abuse score: ${abuseScore}`);
            return denyResponse("Access token issuance is blocked due to high IP risk.");
        }

        if (abuseScore < 25) {
            console.log(`Allowed token issuance: Low abuse score (${abuseScore}). No modifications applied.`);
            return allowResponse();
        }

        // Determine expiry based on score and login time
        let expiry;
        if (isWorkingHours()) {
            expiry = EXPIRY_WORKING_HOURS; // 15 mins for low risk during working hours
        } else {
            expiry = EXPIRY_NON_WORKING_HOURS; // 5 mins for low risk outside working hours
        }

        console.log(`Allowing token issuance with expiry: ${expiry} seconds`);

        return {
            statusCode: 200,
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                actionStatus: "SUCCESS",
                operations: [
                    {
                        op: "replace",
                        path: "/accessToken/claims/expires_in",
                        value: expiry.toString()
                    }
                ]
            })
        };
    } catch (err) {
        console.error("Error during AbuseIPDB lookup:", err.message);
        return denyResponse();
    }
};

function denyResponse(reason) {
    return {
        statusCode: 200,
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            actionStatus: "FAILED",
            failureReason: "access_denied",
            failureDescription: reason
        })
    };
}

function allowResponse() {
    return {
        statusCode: 200,
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            actionStatus: "SUCCESS"
        })
    };
}
