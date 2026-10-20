# Scam

## Persistent database storage

The backend stores its SQLite database at `./data/honeypot.db` by default. The
directory is created automatically before a database connection is opened.
Override the database file location with the `DATABASE_PATH` environment
variable when the runtime's persistent mount is elsewhere.

SQLite files must live on persistent storage in cloud deployments; otherwise,
the database can be lost when an instance is replaced or redeployed.

- **Render:** Attach a Persistent Disk and set `DATABASE_PATH` to a file under
  its mount path (for example, `/var/data/honeypot.db` if the disk is mounted at
  `/var/data`).
- **Railway:** Add a Volume, mount it at `/data`, and set
  `DATABASE_PATH=/data/honeypot.db`.
- **Docker:** Mount a host directory or named volume to the app's `./data`
  directory (for example, `-v ./data:/app/data` when the app runs from `/app`).
  Alternatively set `DATABASE_PATH` to a file inside the mounted directory.

Ensure the application has write permission to the mounted directory.
