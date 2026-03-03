create type public.rol_usuario as enum
('alumno', 'profesor', 'admin')

ALTER TYPE PUBLIC.rol_usuario
OWNER TO POSTGRES;

CREATE TABLE USERS (
id_user serial primary key,
user_name Varchar () not null,
password Varchar () not null,
user_email Varchar () not null,
creado_en timestamp with time zone () not null,
actualizado_en timestamp with time zone () not null,
rol rol_usuario () not null
);
-- Para crear eventos uso estas tablas
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id_user) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    event_date DATE NOT NULL,
    event_time TIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(event_date);