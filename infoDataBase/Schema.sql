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