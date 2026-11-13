-- Failed release-notes runs per release; after 5 the notes are given up on.
ALTER TABLE releases ADD COLUMN notes_attempts int NOT NULL DEFAULT 0;
