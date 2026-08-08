-- =============================================================================
-- 0008 — Canonical permission catalogue, built-in roles, default configuration
--
-- The catalogue here MUST match `modules::authorization::catalog::PERMISSIONS` in
-- the Rust source. A startup check compares the two and refuses to boot on
-- divergence, so a permission cannot exist in code but be missing from the
-- database (which would silently deny) or exist in the database but not in code
-- (which would be an ungoverned grant).
-- =============================================================================

INSERT INTO permissions (code, module, description, max_principal_type, is_dangerous) VALUES
-- --- Identity & access management -------------------------------------------
('iam.users.read',             'iam',         'View user accounts',                              'INTERNAL', false),
('iam.users.create',           'iam',         'Create user accounts directly',                   'INTERNAL', false),
('iam.users.update',           'iam',         'Modify user profile fields',                      'INTERNAL', false),
('iam.users.suspend',          'iam',         'Suspend or reactivate a user account',            'INTERNAL', false),
('iam.users.archive',          'iam',         'Archive a user account',                          'INTERNAL', false),
('iam.users.invite',           'iam',         'Issue invitations to new users',                  'INTERNAL', false),
('iam.roles.read',             'iam',         'View roles and their permissions',                'INTERNAL', false),
('iam.roles.create',           'iam',         'Create custom roles',                             'INTERNAL', false),
('iam.roles.update',           'iam',         'Modify a role and its permission set',            'INTERNAL', false),
('iam.roles.delete',           'iam',         'Delete a non-system role',                        'INTERNAL', false),
-- Dangerous: assigning a role is how authority actually reaches a person.
('iam.roles.assign',           'iam',         'Assign or unassign roles for a user',             'INTERNAL', true),
('iam.permissions.read',       'iam',         'View the permission catalogue',                   'INTERNAL', false),
-- Dangerous: this is the direct per-user grant path and the sharpest escalation edge.
('iam.permissions.delegate',   'iam',         'Create or remove per-user permission overrides',   'INTERNAL', true),
('iam.sessions.read',          'iam',         'View sessions belonging to other users',          'INTERNAL', false),
-- Dangerous: revoking sessions is an availability weapon as well as a control.
('iam.sessions.revoke',        'iam',         'Revoke sessions belonging to other users',        'INTERNAL', true),

-- --- Company structure -------------------------------------------------------
('departments.read',           'departments', 'View departments',                                'INTERNAL', false),
('departments.create',         'departments', 'Create departments',                              'INTERNAL', false),
('departments.update',         'departments', 'Modify departments',                              'INTERNAL', false),
('departments.archive',        'departments', 'Archive departments',                             'INTERNAL', false),
('departments.members.manage', 'departments', 'Add or remove department members',                'INTERNAL', false),

-- --- External clients --------------------------------------------------------
('clients.read',               'clients',     'View client accounts',                            'INTERNAL', false),
('clients.create',             'clients',     'Create client accounts',                          'INTERNAL', false),
('clients.update',             'clients',     'Modify client accounts',                          'INTERNAL', false),
('clients.archive',            'clients',     'Archive client accounts',                         'INTERNAL', false),
('clients.members.manage',     'clients',     'Manage client account memberships',               'INTERNAL', false),

-- --- Operations --------------------------------------------------------------
('projects.read',              'projects',    'View internal projects',                          'INTERNAL', false),
('projects.create',            'projects',    'Create projects',                                 'INTERNAL', false),
('projects.update',            'projects',    'Modify projects',                                 'INTERNAL', false),
('projects.archive',           'projects',    'Archive projects',                                'INTERNAL', false),
('projects.members.manage',    'projects',    'Add or remove internal project members',          'INTERNAL', false),
-- Dangerous: this is the control that moves company data across the external
-- trust boundary. It is the single most consequential business permission.
('projects.clients.share',     'projects',    'Share or unshare a project with a client account','INTERNAL', true),
('tasks.read',                 'tasks',       'View tasks',                                      'INTERNAL', false),
('tasks.create',               'tasks',       'Create tasks',                                    'INTERNAL', false),
('tasks.update',               'tasks',       'Modify tasks, including client visibility',       'INTERNAL', false),
('tasks.assign',               'tasks',       'Assign or unassign task assignees',               'INTERNAL', false),
('tasks.delete',               'tasks',       'Cancel a task',                                   'INTERNAL', false),

-- --- Platform ----------------------------------------------------------------
('settings.read',              'settings',    'Read non-sensitive system settings and flags',    'INTERNAL', false),
('settings.features.write',    'settings',    'Toggle non-security feature flags',               'INTERNAL', false),
-- Dangerous: registration mode and security policy live here.
('settings.security.write',    'settings',    'Change security-sensitive settings',              'INTERNAL', true),
('audit.read',                 'audit',       'Read the audit log',                              'INTERNAL', false),

-- --- Client portal -----------------------------------------------------------
-- The ONLY two permissions an external principal can ever hold. Everything above
-- is max_principal_type = 'INTERNAL' and is refused for a CLIENT before any grant
-- is even looked up (docs/backend/04-authorization.md §5 step 3).
('client.portal.projects.read','client_portal','View projects explicitly shared with your client account', 'ANY', false),
('client.portal.tasks.read',   'client_portal','View tasks explicitly marked client-visible',              'ANY', false);

-- =============================================================================
-- Built-in roles
--
-- Fixed UUIDs so that the roles are stable across environments and can be
-- referenced by tests and operational documentation.
-- =============================================================================
INSERT INTO roles (id, code, name, description, is_system, allowed_principal_type) VALUES
('00000000-0000-7000-8000-000000000001', 'system_administrator', 'System Administrator',
 'Broad administrative authority. Deliberately EXCLUDES permission delegation and security settings, both of which the owner grants explicitly. Subordinate to system ownership in every case.',
 true, 'INTERNAL'),
('00000000-0000-7000-8000-000000000002', 'employee', 'Employee',
 'Least-privilege baseline for internal staff. Sees only what they are assigned to.',
 true, 'INTERNAL'),
('00000000-0000-7000-8000-000000000003', 'client_user', 'Client User',
 'External baseline. Sees only projects explicitly shared with an active client account they belong to.',
 true, 'CLIENT');

-- --- system_administrator ----------------------------------------------------
-- Note what is ABSENT: iam.permissions.delegate and settings.security.write.
-- "Administrator" must not become an invisible second owner (brief §91), so the
-- two permissions that would let it manufacture arbitrary authority are withheld
-- and must be granted deliberately, by the owner, per person.
INSERT INTO role_permissions (role_id, permission_code, scope_type)
SELECT '00000000-0000-7000-8000-000000000001', code, 'GLOBAL'
  FROM permissions
 WHERE code IN (
    'iam.users.read', 'iam.users.create', 'iam.users.update', 'iam.users.suspend',
    'iam.users.archive', 'iam.users.invite',
    'iam.roles.read', 'iam.roles.create', 'iam.roles.update', 'iam.roles.delete', 'iam.roles.assign',
    'iam.permissions.read', 'iam.sessions.read', 'iam.sessions.revoke',
    'departments.read', 'departments.create', 'departments.update', 'departments.archive',
    'departments.members.manage',
    'clients.read', 'clients.create', 'clients.update', 'clients.archive', 'clients.members.manage',
    'projects.read', 'projects.create', 'projects.update', 'projects.archive',
    'projects.members.manage', 'projects.clients.share',
    'tasks.read', 'tasks.create', 'tasks.update', 'tasks.assign', 'tasks.delete',
    'settings.read', 'settings.features.write',
    'audit.read'
 );

-- --- employee ----------------------------------------------------------------
-- A new employee can see their own record, their department, and the projects and
-- tasks they are actually assigned to. Nothing else. Least privilege is the
-- default, not an option an administrator has to remember to choose.
INSERT INTO role_permissions (role_id, permission_code, scope_type) VALUES
('00000000-0000-7000-8000-000000000002', 'iam.users.read',    'SELF'),
('00000000-0000-7000-8000-000000000002', 'departments.read',  'DEPARTMENT'),
('00000000-0000-7000-8000-000000000002', 'projects.read',     'ASSIGNED'),
('00000000-0000-7000-8000-000000000002', 'tasks.read',        'ASSIGNED'),
('00000000-0000-7000-8000-000000000002', 'tasks.update',      'ASSIGNED');

-- --- client_user -------------------------------------------------------------
-- Holding this role grants NO visibility on its own. Visibility comes from an
-- ACTIVE client membership joined to a live project_client_link. A client with
-- this role and no membership sees an empty world.
INSERT INTO role_permissions (role_id, permission_code, scope_type) VALUES
('00000000-0000-7000-8000-000000000003', 'client.portal.projects.read', 'ASSIGNED'),
('00000000-0000-7000-8000-000000000003', 'client.portal.tasks.read',    'ASSIGNED');

-- =============================================================================
-- Default configuration — secure by default
-- =============================================================================
INSERT INTO system_settings (key, value, value_type, is_security_sensitive, description) VALUES
-- INVITE_ONLY, not CLIENT_SELF_REGISTRATION: a fresh installation must not accept
-- self-registration until an operator deliberately turns it on.
('registration.mode', '"INVITE_ONLY"'::jsonb, 'ENUM', true,
 'DISABLED | INVITE_ONLY | CLIENT_SELF_REGISTRATION. Self-registration can only ever create CLIENT principals.'),
('invitations.ttl_hours', '72'::jsonb, 'INTEGER', false,
 'Lifetime of an invitation token in hours.'),
('sessions.max_per_user', '20'::jsonb, 'INTEGER', true,
 'Upper bound on concurrent live sessions per user; the oldest is revoked beyond this.');

INSERT INTO feature_flags (key, enabled, is_security_sensitive, description) VALUES
-- Implemented in this scope.
('client_portal', true,  true,  'External client portal endpoints. Disabling this does NOT replace authorization; every client route is independently authorized.'),
-- Not implemented. These exist so the toggle surface is designed once, and they
-- are false because a flag for an unbuilt module must never read as "available".
('chat',          false, false, 'Realtime chat. NOT IMPLEMENTED — see docs/backend/11-future-realtime.md'),
('crm',           false, false, 'CRM module. NOT IMPLEMENTED'),
('finance',       false, false, 'Finance module. NOT IMPLEMENTED'),
('files',         false, false, 'File storage. NOT IMPLEMENTED — see docs/backend/12-future-storage.md'),
('approvals',     false, false, 'Approval workflows. NOT IMPLEMENTED'),
('ai.assistant',  false, true,  'AI/MCP assistant. NOT IMPLEMENTED — see docs/backend/10-future-ai-mcp-security.md');
