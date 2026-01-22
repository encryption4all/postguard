\connect "devdb";

DROP TABLE IF EXISTS "api_keys";
CREATE TABLE "public"."api_keys" (
    "key" character varying(128) DEFAULT '' NOT NULL,
    "email" character varying(256) NOT NULL,
    "attributes" json DEFAULT '{}' NOT NULL,
    "expires_at" timestamp NOT NULL,
    CONSTRAINT "api_keys_pkey" PRIMARY KEY ("key")
);

INSERT INTO "api_keys" ("key", "email", "attributes", "expires_at") VALUES
('PG-API-hallo',	'test@test.com',	'{}',	'3000-01-08 04:05:06');
