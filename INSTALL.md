# Install PostgreSQL

<https://www.postgresql.org/download/>

# Create tables

```
CREATE SCHEMA "access";

CREATE TABLE "access"."resource" (
  "id" serial NOT NULL,
  "name" character varying NOT NULL,
  "url" character varying NULL,
  "locked" boolean NOT NULL DEFAULT 'false',
  "public" boolean NOT NULL DEFAULT 'false'
);
ALTER TABLE "access"."resource"
  ADD CONSTRAINT "resource_id" PRIMARY KEY ("id"),
  ADD CONSTRAINT "resource_name" UNIQUE ("name");

CREATE TABLE "access"."role" (
  "id" serial NOT NULL,
  "name" character varying NOT NULL,
  "priority" integer NOT NULL DEFAULT '0'
);
ALTER TABLE "access"."role"
  ADD CONSTRAINT "role_id" PRIMARY KEY ("id"),
  ADD CONSTRAINT "role_name" UNIQUE ("name");

INSERT INTO "role" ("name", "priority") VALUES ('admin', '9');

CREATE TABLE "access"."role_resource" (
  "id_role" integer NOT NULL,
  "id_resource" integer NOT NULL,
  "locked" boolean NOT NULL DEFAULT 'false'
);
ALTER TABLE "access"."role_resource"
  ADD CONSTRAINT "role_resource_id_role_id_resource" PRIMARY KEY ("id_role", "id_resource"),
  ADD FOREIGN KEY ("id_role") REFERENCES "access"."role" ("id"),
  ADD FOREIGN KEY ("id_resource") REFERENCES "access"."resource" ("id");

CREATE TABLE "access"."user" (
  "id" serial NOT NULL,
  "login" character varying(15) NOT NULL,
  "password" character varying NOT NULL,
  "email" character varying NOT NULL,
  "fullname" character varying NOT NULL,
  "home" integer NOT NULL,
  "locked" boolean NOT NULL DEFAULT 'false'
);
ALTER TABLE "access"."user"
  ADD CONSTRAINT "user_id" PRIMARY KEY ("id"),
  ADD CONSTRAINT "user_login" UNIQUE ("login"),
  ADD CONSTRAINT "user_email" UNIQUE ("email"),
  ADD FOREIGN KEY ("home") REFERENCES "access"."resource" ("id");

CREATE TABLE "access"."user_role" (
  "id_user" integer NOT NULL,
  "id_role" integer NOT NULL
);
ALTER TABLE "access"."user_role"
  ADD CONSTRAINT "user_role_id_user_id_role" PRIMARY KEY ("id_user", "id_role"),
  ADD FOREIGN KEY ("id_user") REFERENCES "access"."user" ("id"),
  ADD FOREIGN KEY ("id_role") REFERENCES "access"."role" ("id");

CREATE OR REPLACE FUNCTION admin_resource()
  RETURNS trigger AS
$$
DECLARE id INT;
BEGIN
  SELECT r."id" INTO id FROM "access"."role" r WHERE r."name" = 'admin';
  INSERT INTO "access"."role_resource" VALUES (id, NEW.id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_resource AFTER INSERT ON "access"."resource" FOR EACH ROW EXECUTE PROCEDURE admin_resource();
```
