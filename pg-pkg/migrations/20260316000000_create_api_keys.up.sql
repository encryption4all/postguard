CREATE TABLE IF NOT EXISTS api_keys
(
    id                        UUID         DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    api_key                   VARCHAR(128) DEFAULT '' NOT NULL UNIQUE,
    email                     VARCHAR(256)           NOT NULL,
    organisation_name         VARCHAR(256),
    phone_number              VARCHAR(32),
    kvk_number                VARCHAR(32),
    organisation_name_public  BOOLEAN      NOT NULL DEFAULT true,
    phone_number_public       BOOLEAN      NOT NULL DEFAULT false,
    kvk_number_public         BOOLEAN      NOT NULL DEFAULT false,
    expires_at                TIMESTAMP              NOT NULL
);
