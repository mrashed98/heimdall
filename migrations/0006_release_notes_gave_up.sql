-- A release whose notes could not be fetched after repeated failures is
-- `gave_up`, distinct from `none` (no notes exist).
ALTER TABLE releases DROP CONSTRAINT releases_notes_class_check;
ALTER TABLE releases ADD CONSTRAINT releases_notes_class_check
    CHECK (notes_class IN ('cve_affecting', 'security', 'bugfix', 'plain', 'none', 'gave_up'));
