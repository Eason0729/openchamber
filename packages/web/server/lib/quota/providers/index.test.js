import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import fs from 'fs';
import os from 'os';
import path from 'path';

let rootDir;
let homeDir;
let configPath;
let authPath;
let providers;

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

describe('quota provider registry', () => {
  beforeAll(async () => {
    rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-quota-'));
    homeDir = path.join(rootDir, 'home');
    configPath = path.join(rootDir, 'config', 'opencode.json');
    authPath = path.join(homeDir, '.local', 'share', 'opencode', 'auth.json');

    fs.mkdirSync(homeDir, { recursive: true });
    process.env.HOME = homeDir;
    process.env.OPENCODE_CONFIG = configPath;

    providers = await import('./index.js');
  });

  beforeEach(() => {
    fs.rmSync(authPath, { force: true });
    fs.rmSync(configPath, { force: true });
  });

  afterAll(() => {
    fs.rmSync(rootDir, { recursive: true, force: true });
    delete process.env.HOME;
    delete process.env.OPENCODE_CONFIG;
  });

  test('lists providers when auth file is empty but provider config has credentials', () => {
    writeJson(configPath, {
      provider: {
        openrouter: {
          options: {
            key: 'plugin-key'
          }
        }
      }
    });

    expect(providers.listConfiguredQuotaProviders()).toContain('openrouter');
  });
});
