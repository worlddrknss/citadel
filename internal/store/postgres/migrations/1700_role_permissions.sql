-- Role permissions policies (2.7): what an assumed role's temporary
-- credentials may do. An empty policy keeps the role's sessions
-- unrestricted within the account (the behaviour before 2.7); a non-empty
-- one is an IAM-style identity policy, deny by default. iam_roles is small,
-- so adding a defaulted column is instant.
ALTER TABLE iam_roles ADD COLUMN IF NOT EXISTS permissions_policy TEXT NOT NULL DEFAULT '';
