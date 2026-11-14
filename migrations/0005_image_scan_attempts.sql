-- Failed image scans per digest. scan-images reports each failure; pending
-- images are offered least recently tried first, and a digest that failed 5
-- times is offered again only a day after its last try.
CREATE TABLE image_scan_attempts (
    digest          text PRIMARY KEY,
    attempts        int NOT NULL DEFAULT 0,
    last_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text NOT NULL DEFAULT ''
);
