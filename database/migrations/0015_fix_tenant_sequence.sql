-- ABOUTME: Fix tenant ID sequence after seeded data insertion
-- ABOUTME: Ensures auto-increment continues correctly after migration 0010 seeded tenant ID 1

-- Reset sequence to continue from highest existing tenant ID
-- Uses COALESCE to handle empty table case
SELECT setval('tenants_id_seq', (SELECT COALESCE(MAX(id), 1) FROM tenants));
