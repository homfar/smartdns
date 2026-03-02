CREATE INDEX IF NOT EXISTS idx_records_zone_name_type ON records(zone_id, name, type);
CREATE INDEX IF NOT EXISTS idx_zones_domain ON zones(domain);
CREATE INDEX IF NOT EXISTS idx_sync_audit_created_at ON sync_audit(created_at DESC);
