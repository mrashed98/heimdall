-- An all-realms oath matches the same service name in any realm, so the oath
-- carries the service name itself. service_id is no longer set by Heimdall:
-- its ON DELETE CASCADE would erase oaths (kept forever) with the service.
ALTER TABLE oaths ADD COLUMN service_name text;
UPDATE oaths SET service_name = s.name FROM services s WHERE s.id = oaths.service_id;
ALTER TABLE oaths ALTER COLUMN service_name SET NOT NULL;
ALTER TABLE oaths ALTER COLUMN service_id DROP NOT NULL;
CREATE INDEX oaths_lookup_idx ON oaths (advisory_id, name_key, service_name) WHERE status = 'active';
