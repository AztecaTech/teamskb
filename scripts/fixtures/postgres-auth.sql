CREATE ROLE iqkb_service LOGIN NOINHERIT PASSWORD 'IQKB-test-service-only';
CREATE ROLE iqkb_alex NOLOGIN;
CREATE ROLE iqkb_blair NOLOGIN;
CREATE ROLE iqkb_application NOLOGIN;
CREATE ROLE iqkb_unsafe NOLOGIN BYPASSRLS;
CREATE ROLE iqkb_owner NOLOGIN;
CREATE ROLE iqkb_ungranted NOLOGIN;
GRANT iqkb_alex, iqkb_blair, iqkb_application, iqkb_unsafe, iqkb_owner TO iqkb_service;
CREATE SCHEMA iqkb_auth;
CREATE TABLE iqkb_auth.users(tenant_id text,email text,user_id text,database_role text,active boolean,permission_version text);
INSERT INTO iqkb_auth.users VALUES
('tenant-one','alex@example.com','alex','iqkb_alex',true,'v1'),
('tenant-one','blair@example.com','blair','iqkb_blair',true,'v1'),
('tenant-one','app-alex@example.com','alex','iqkb_application',true,'v1'),
('tenant-one','app-blair@example.com','blair','iqkb_application',true,'v1'),
('tenant-one','inactive@example.com','disabled','iqkb_alex',false,'v1'),
('tenant-one','duplicate@example.com','alex','iqkb_alex',true,'v1'),
('tenant-one','duplicate@example.com','blair','iqkb_blair',true,'v1'),
('tenant-one','unsafe@example.com','unsafe','iqkb_unsafe',true,'v1'),
('tenant-one','service@example.com','service','iqkb_service',true,'v1'),
('tenant-one','owner@example.com','owner','iqkb_owner',true,'v1'),
('tenant-one','ungranted@example.com','ungranted','iqkb_ungranted',true,'v1');
GRANT USAGE ON SCHEMA iqkb_auth TO iqkb_service;
GRANT SELECT ON iqkb_auth.users TO iqkb_service;
CREATE VIEW iqkb_auth.external_members AS SELECT user_id AS id,email,database_role AS role,active AS enabled FROM iqkb_auth.users WHERE tenant_id='tenant-one';
GRANT SELECT ON iqkb_auth.external_members TO iqkb_service;
CREATE VIEW iqkb_auth.permission_directory AS SELECT user_id AS id,email,CASE WHEN user_id='alex' THEN 'Reader' ELSE 'Editor' END AS role,active AS enabled FROM iqkb_auth.users WHERE email IN ('app-alex@example.com','app-blair@example.com');
GRANT SELECT ON iqkb_auth.permission_directory TO iqkb_service;
CREATE SCHEMA iqkb_data;
GRANT USAGE ON SCHEMA iqkb_data TO iqkb_alex,iqkb_blair,iqkb_application,iqkb_service;
CREATE TABLE iqkb_data.documents(id text PRIMARY KEY,title text,content text,source_url text,owner_id text);
INSERT INTO iqkb_data.documents VALUES ('alex-doc','Policy','Alex private policy','https://example.com/alex','alex'),('blair-doc','Policy','Blair private policy','https://example.com/blair','blair');
ALTER TABLE iqkb_data.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY native_permissions ON iqkb_data.documents TO iqkb_alex,iqkb_blair USING (current_user='iqkb_'||owner_id);
CREATE POLICY application_permissions ON iqkb_data.documents TO iqkb_application USING (owner_id=current_setting('iqkb.user_id',true) AND owner_id=(current_setting('request.jwt.claims',true)::jsonb->>'sub'));
GRANT SELECT(id,title,content,source_url,owner_id) ON iqkb_data.documents TO iqkb_alex,iqkb_blair,iqkb_application;
GRANT UPDATE(title) ON iqkb_data.documents TO iqkb_alex,iqkb_blair,iqkb_application;
CREATE TABLE iqkb_data.service_secret(id text);
GRANT SELECT ON iqkb_data.service_secret TO iqkb_service;
CREATE TABLE iqkb_data.owner_table(id text);
ALTER TABLE iqkb_data.owner_table OWNER TO iqkb_owner;
