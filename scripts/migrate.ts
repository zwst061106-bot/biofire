/**
 * Database migration script
 */

import { mkdirSync } from 'fs';

mkdirSync('./data', { recursive: true });
console.log('Database directories initialized');
