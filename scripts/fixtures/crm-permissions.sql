-- Disposable validation database only; never applied to the CRM database.
CREATE ROLE iqkb_bridge_fixture LOGIN PASSWORD 'IQKB-bridge-fixture-only';
CREATE TABLE public.auth_users (
  id integer PRIMARY KEY, email text NOT NULL, role text NOT NULL, enabled boolean NOT NULL,
  "twoFactorEnabled" boolean NOT NULL DEFAULT false, "force2FA" boolean NOT NULL DEFAULT false,
  "lastLogin" timestamp, "updatedAt" timestamp, "refreshTokenHash" text
);
INSERT INTO public.auth_users(id,email,role,enabled,"force2FA") VALUES
  (7,'person@example.com','custom label',true,false),
  (8,'other@example.com','another label',true,false),
  (9,'disabled@example.com','custom label',false,false),
  (10,'pending@example.com','custom label',true,true);
CREATE TABLE public.system_settings(key text PRIMARY KEY,value jsonb);
INSERT INTO public.system_settings VALUES('require_2fa','false');
CREATE TABLE public.customers(id integer PRIMARY KEY,company text,"transmittingPassword" text);
INSERT INTO public.customers VALUES(1,'Visible company','fixture-secret'),(2,'Another company','fixture-secret');
CREATE TABLE public.prospects(id integer PRIMARY KEY,name text,email text,notes jsonb);
CREATE TABLE public.marketing(id integer PRIMARY KEY,title text,description text,notes jsonb);
CREATE TABLE public.tickets(id integer PRIMARY KEY,"ticketNo" text,company text,items jsonb,"officeNotes" text);
GRANT SELECT ON ALL TABLES IN SCHEMA public TO iqkb_bridge_fixture;
