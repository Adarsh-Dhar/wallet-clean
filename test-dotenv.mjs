import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const apiServerPath = path.join(__dirname, 'artifacts/api-server');
const rootEnvPath = path.resolve(apiServerPath, '../../.env');

console.log('Loading from:', rootEnvPath);
console.log('File exists:', fs.existsSync(rootEnvPath));

const result = dotenv.config({ path: rootEnvPath });
console.log('dotenv result:', result);
console.log('REAL_ONCHAIN:', process.env.REAL_ONCHAIN);
console.log('QUARANTINE_PACKAGE_ID:', process.env.QUARANTINE_PACKAGE_ID?.substring(0, 30) + '...');
