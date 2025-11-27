-- ABOUTME: Drop global unique constraint on oauth_applications.client_id
-- ABOUTME: Migration 0010 creates tenant-scoped constraint but the original global constraint from 0004 still exists

-- Drop the global unique constraint that prevents multiple tenants from using same client_id
-- This was created by migration 0004 with "client_id TEXT NOT NULL UNIQUE"
-- PostgreSQL auto-named it oauth_applications_client_id_key
ALTER TABLE oauth_applications DROP CONSTRAINT IF EXISTS oauth_applications_client_id_key;
