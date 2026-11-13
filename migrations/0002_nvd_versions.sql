-- Component versions a vendor:product was backfilled for. A component version
-- not listed here has not seen the older CVEs yet, so the product is
-- backfilled again.
ALTER TABLE nvd_products ADD COLUMN versions text[] NOT NULL DEFAULT '{}';
