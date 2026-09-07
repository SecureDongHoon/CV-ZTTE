-- Atomic replay/freshness guard (spec §11): a single EVAL executes the whole
-- nonce-insertion + sequence-validation + commit as one atomic step, so
-- concurrent duplicate requests cannot race past the check.
--   KEYS[1] = per-session nonce set key
--   KEYS[2] = per-session sequence key
--   ARGV[1] = nonce (>=128-bit hex)
--   ARGV[2] = monotonic sequence number
--   ARGV[3] = nonce TTL seconds
-- Returns: 'OK' | 'NONCE_REPLAY' | 'SEQUENCE_INVALID'
local nonce_key = KEYS[1]
local seq_key = KEYS[2]
local nonce = ARGV[1]
local seq = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

if redis.call('SISMEMBER', nonce_key, nonce) == 1 then
  return 'NONCE_REPLAY'
end

local last = tonumber(redis.call('GET', seq_key) or '-1')
if seq <= last then
  return 'SEQUENCE_INVALID'
end

redis.call('SADD', nonce_key, nonce)
redis.call('EXPIRE', nonce_key, ttl)
redis.call('SET', seq_key, seq)
return 'OK'
