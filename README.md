# PhishLab

## Deploy on Vercel with Neon

Vercel runs the FastAPI application as a serverless function. Neon PostgreSQL
stores application data persistently; the app uses SQLite locally when
`DATABASE_URL` is not set.

1. Create a Neon project and database in Singapore (`aws-ap-southeast-1`) to
   keep it near the Vercel function region. Copy the **pooled** PostgreSQL
   connection string from the Neon dashboard.
2. In Vercel, open the project connected to this repository and go to
   **Settings > Environment Variables**.
3. Add `DATABASE_URL` with the Neon pooled connection string, and add
   `OPENAI_API_KEY` with your OpenAI API key. Keep both values private.
4. Optionally add `OPENAI_MODEL`; it defaults to `gpt-4o-mini`.
5. Apply the variables to **Production** (and use a separate Neon database for
   Preview deployments if you enable them). Redeploy the latest commit.
6. Open the deployment URL. The `vercel.json` file configures the FastAPI
   function, while the frontend is served from the `frontend` directory.

The PostgreSQL tables are created automatically when the application starts.
The Vercel deployment intentionally fails at startup if `DATABASE_URL` is
missing, rather than silently storing data in a temporary local filesystem.
Existing local SQLite records are not migrated automatically; the hosted
database starts empty.
The Neon Free plan scales compute to zero after inactivity, so the first
database request after an idle period can take longer even though stored data
remains persistent.

The app sends conversation messages and system instructions to OpenAI for
generated replies and structured observations. Use fictional data and review
OpenAI's data-handling terms before deployment. For local AI setup, see
[OPENAI_SETUP.md](./OPENAI_SETUP.md).
