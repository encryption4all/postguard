CREATE TABLE IF NOT EXISTS api_keys
(
    key        VARCHAR(128) DEFAULT '' NOT NULL PRIMARY KEY,
    email      VARCHAR(256)           NOT NULL,
    attributes JSON         DEFAULT '{}' NOT NULL,
    expires_at TIMESTAMP              NOT NULL
);
