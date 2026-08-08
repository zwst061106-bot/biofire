/**
 * Database persistence layer
 * Supports SQLite (dev) and PostgreSQL (production)
 */

import { createClient } from 'redis';

let redis: ReturnType<typeof createClient> | null = null;

export async function getRedisClient() {
  if (!redis) {
    redis = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
    await redis.connect();
  }
  return redis;
}

export async function setCache(key: string, value: string, ttlSeconds: number = 3600): Promise<void> {
  const client = await getRedisClient();
  await client.setEx(key, ttlSeconds, value);
}

export async function getCache(key: string): Promise<string | null> {
  const client = await getRedisClient();
  return client.get(key);
}

export async function delCache(key: string): Promise<void> {
  const client = await getRedisClient();
  await client.del(key);
}
