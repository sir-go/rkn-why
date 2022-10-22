select ip
from ip_block
where
  (
    inet_aton(substring_index(ip, '/', 1)) & (
      ~(
        -1 << convert(substring_index(ip, '/', -1), unsigned integer)
      ) << 32 - convert(substring_index(ip, '/', -1), unsigned integer)
    )
  ) = (
    inet_aton(?) & (
      ~(
        -1 << convert(substring_index(ip, '/', -1), unsigned integer)
      ) << 32 - convert(substring_index(ip, '/', -1), unsigned integer)
    )
  )
limit 1;

select
  hostname
from https_domains
where
  hostname = ?
  or
  ? like concat('%.', hostname)
