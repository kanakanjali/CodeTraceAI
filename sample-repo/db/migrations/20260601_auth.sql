alter table sessions add column rotated_at timestamptz;
create index sessions_user_id_idx on sessions(user_id);
