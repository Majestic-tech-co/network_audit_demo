-- NetAudit database initialisation
-- Tables are created by SQLAlchemy on startup.
-- This file sets up extensions and sensible defaults.

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for fast text search on findings
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Set timezone
SET timezone = 'UTC';
