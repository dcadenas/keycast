-- ABOUTME: Add tenant_id to permissions table
-- ABOUTME: This was missing from migration 0010_multi_tenancy.sql

-- Add tenant_id to permissions table
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_permissions_tenant_id ON permissions(tenant_id);
