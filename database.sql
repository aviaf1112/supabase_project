select
  table_name,
  column_name,
  data_type
from
  information_schema.columns
where
  table_schema = 'public';