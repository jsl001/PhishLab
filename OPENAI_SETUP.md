# Configure the OpenAI assistant

The app uses the OpenAI API to generate persona replies and structured
observations. Conversation messages and the app's system instructions are sent
to OpenAI as part of those requests. Use fictional data and review OpenAI's
data-handling terms before using the app.

1. Create an OpenAI API key in your OpenAI account.
2. Set `OPENAI_API_KEY` in the environment where the app runs. For local
   development, put it in the repository-root `.env` file. For Render, set it
   as a secret environment variable in the service settings.
3. Optionally set `OPENAI_MODEL` to a model available to your account. The
   default is `gpt-4o-mini`.
4. From the repository root, install the Python dependencies and start the
   FastAPI app:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m uvicorn main:app --reload
   ```
5. Open [http://127.0.0.1:8000](http://127.0.0.1:8000). AI features require a
   valid API key and network access to OpenAI.

The page opens on **Why it matters**. The sidebar separates that overview from
**What PhishLab does**, the **Questions you may ask** FAQ, and the
**Conversation lab**. The What PhishLab does page includes a persona comparison
that sends the same fictional message to all three personas through the local
model; comparison replies are not added to chat history or analytics.
Model-generated stages and pressure levels are illustrative assessments, not
verified findings. The conversation lab also shows a rule-based score from the
latest five messages. Its 50-point review threshold and pattern flags are
heuristics for research exploration, not a validated scam verdict; review the
messages and context before drawing conclusions.
In the guided simulation, next-turn choices reflect whether the persona asked a
question or set a boundary. They are predefined, abstract awareness cues rather
than generated scam scripts; operational details are intentionally omitted.

## Singapore scam-advisory keywords

At startup and every six hours, the backend reads the ScamShield homepage and
any configured official ScamShield/SPF RSS feeds for scam-related phrases. It
uses those phrases as literal-match classifier cues; feed text is never treated
as a regular expression. The classifier also checks fixed patterns for CDC
voucher phishing, government impersonation, and local payment traps. Feed
availability is logged, and the existing fixed rules remain active if an
advisory source is unavailable.

Set `SCAM_ADVISORY_RSS_URLS` in the repository-root `.env` to a comma-separated
list of official HTTPS RSS feed URLs. Only `scamshield.gov.sg` and
`police.gov.sg` hosts (including their subdomains) are accepted. The provided
ScamShield homepage URL is an HTML page, not an RSS feed; use this setting for
the actual RSS feed endpoint(s) when available.

## Optional URL reputation checks

The conversation panel can submit a URL to Google Safe Browsing on demand. The
app does not open the submitted URL or follow redirects. When a check is
submitted, the full URL—including its path and query string—is sent to Google;
the app does not store the checked URL. Without a key, the endpoint reports
that checking is not configured and does not send the URL.

To enable it, enable the Google Safe Browsing API in a Google Cloud project and
add a restricted API key to the repository-root `.env` file:

```dotenv
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key
```

Restrict the key to the Safe Browsing API and apply suitable quota limits. Do
not commit the key, and restart the FastAPI server after changing `.env`.
Google's Safe Browsing API is for non-commercial use; for a commercial
deployment, use Google Web Risk instead and review its terms.

A threat-list match is reported as a potential threat. “No known threat” only
means no match was returned at check time; it is not a safety guarantee.
