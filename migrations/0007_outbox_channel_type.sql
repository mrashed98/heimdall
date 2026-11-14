-- Each outbox row records the type of channel it was rendered for, so a
-- channel renamed to another type never receives a payload of the old one.
-- Rows queued before this migration were Teams cards.
ALTER TABLE outbox ADD COLUMN channel_type text NOT NULL DEFAULT 'teams';
