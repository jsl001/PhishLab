# Scam

## Deploy on Render

The repository includes a Render Blueprint in `render.yaml`. To deploy:

1. Push this repository to GitHub.
2. In Render, choose **New > Blueprint** and connect the repository.
3. Provide your `OPENAI_API_KEY` when Render prompts for the secret. Do not
   commit the key to the repository.
4. Deploy the Blueprint. Render builds the app and runs it as a web service;
   open the service URL when deployment finishes.

The Blueprint uses a paid Starter web service and a 1 GB persistent disk.
Both SQLite databases are stored on that disk at separate paths so their
schemas do not collide. To change the instance size or disk size, edit
`render.yaml` before deploying.

The app sends conversation messages to OpenAI for generated replies and
structured observations. Use fictional data and review OpenAI's data-handling
terms before deployment. The `OPENAI_MODEL` setting defaults to `gpt-4o-mini`.
For local setup, see [OPENAI_SETUP.md](./OPENAI_SETUP.md).

## Persistent database storage

The conversation database uses `DATABASE_PATH` (default
`./data/honeypot.db`). The auxiliary messages database uses
`MESSAGE_DATABASE_PATH` (default `honeypot.db` in the repository root).
Parent directories are created automatically during startup.

SQLite files must live on persistent storage in cloud deployments; otherwise,
the database can be lost when an instance is replaced or redeployed.

- **Render:** The supplied Blueprint mounts a Persistent Disk at `/var/data`
  and sets both database paths there.
- **Railway:** Add a Volume, mount it at `/data`, and set
  `DATABASE_PATH=/data/honeypot.db` and
  `MESSAGE_DATABASE_PATH=/data/messages.db`.
- **Docker:** Mount a host directory or named volume to the app's `./data`
  directory (for example, `-v ./data:/app/data` when the app runs from `/app`).
  Alternatively set both database path variables to separate files inside the
  mounted directory.

Ensure the application has write permission to the mounted directory.
