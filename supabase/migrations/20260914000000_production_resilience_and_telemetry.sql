-- ============================================================================
-- PACT OS — Phase 11: Production Resilience, Indexing & Audit Telemetry
-- Migration: 20260914000000_production_resilience_and_telemetry.sql
-- ============================================================================

-- 1. Security & Consequence Telemetry Audit Log Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS: Users can only read their own audit logs; server/service role inserts
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own audit logs"
    ON public.audit_logs
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own audit logs"
    ON public.audit_logs
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- 2. Performance & Production Resilience Composite Indexes

-- Fast query optimization for active circle memberships
CREATE INDEX IF NOT EXISTS idx_circle_members_user_status 
    ON public.accountability_circle_members (user_id, status);

CREATE INDEX IF NOT EXISTS idx_circle_members_circle_role 
    ON public.accountability_circle_members (circle_id, role);

-- Fast lookup for pending charity pledges by status and deadline
CREATE INDEX IF NOT EXISTS idx_charity_pledges_status_created 
    ON public.charity_pledges (status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_charity_pledges_user_commitment 
    ON public.charity_pledges (user_id, commitment_id);

-- Fast lookup for unread notifications by user and delivery status
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread 
    ON public.notifications (user_id, is_read) 
    WHERE is_read = false;

-- Fast lookup for audit logs
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created 
    ON public.audit_logs (user_id, created_at DESC);

-- 3. Telemetry Log Function (Security Definer with user boundary)
CREATE OR REPLACE FUNCTION public.record_audit_event(
    p_event_type TEXT,
    p_action TEXT,
    p_resource_type TEXT,
    p_resource_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_log_id UUID;
    v_user_id UUID;
BEGIN
    v_user_id := auth.uid();
    
    INSERT INTO public.audit_logs (
        user_id,
        event_type,
        action,
        resource_type,
        resource_id,
        metadata
    ) VALUES (
        v_user_id,
        p_event_type,
        p_action,
        p_resource_type,
        p_resource_id,
        p_metadata
    ) RETURNING id INTO v_log_id;

    RETURN v_log_id;
END;
$$;
