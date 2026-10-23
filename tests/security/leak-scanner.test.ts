import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

function collectRepoFiles(dir: string, results: string[] = []): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectRepoFiles(fullPath, results);
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

describe('Zero-Leak Security & Privacy Gate', () => {
  it('ensures zero local filesystem paths, OS usernames, or secret tokens exist across repository files', () => {
    const rootDir = process.cwd();
    const files = collectRepoFiles(rootDir);

    const forbiddenPatterns: Array<{ name: string; regex: RegExp }> = [
      { name: 'Linux home directory path', regex: new RegExp('\\/home\\/[a-zA-Z0-9_-]+') },
      { name: 'macOS Users directory path', regex: new RegExp('\\/Users\\/[a-zA-Z0-9_-]+') },
      { name: 'Windows Users directory path', regex: new RegExp('C:\\\\Users\\\\[a-zA-Z0-9_-]+', 'i') },
      { name: 'GitHub PAT token prefix', regex: new RegExp('ghp_[a-zA-Z0-9]{20,}') },
      { name: 'OpenAI/Secret key prefix', regex: new RegExp('sk-[a-zA-Z0-9]{20,}') },
    ];

    for (const filePath of files) {
      const relative = path.relative(rootDir, filePath);
      if (relative.includes('leak-scanner.test.ts') || relative.includes('security-audit.sh')) {
        continue;
      }
      const content = fs.readFileSync(filePath, 'utf8');
      for (const rule of forbiddenPatterns) {
        assert.equal(
          rule.regex.test(content),
          false,
          `Leak detected in ${relative}: matched ${rule.name}`
        );
      }
    }
  });
});
