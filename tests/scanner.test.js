const { describe, it } = require('node:test');
const assert = require('node:assert');
const { 
  calculateShannonEntropy, 
  isLikelyEntropySecret, 
  detectFunctions, 
  diffLines 
} = require('../backend/scanner.ts');

describe('Scanner Logic', () => {
  describe('Shannon Entropy', () => {
    it('should calculate low entropy for repetitive strings', () => {
      assert.ok(calculateShannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
    });

    it('should calculate high entropy for random-looking strings', () => {
      const highEntropyStr = '4f9a2b8c7e1d6f3a0b5c9d8e7f6a5b4c';
      assert.ok(calculateShannonEntropy(highEntropyStr) > 3.5);
    });
  });

  describe('Entropy Secret Detection', () => {
    it('should identify likely secrets', () => {
      const secret = 'sk-proj-4f9a2b8c7e1d6f3a0b5c9d8e7f6a5b4c';
      assert.strictEqual(isLikelyEntropySecret(secret), true);
    });

    it('should reject short strings', () => {
      assert.strictEqual(isLikelyEntropySecret('short'), false);
    });

    it('should reject non-secret-like strings', () => {
      assert.strictEqual(isLikelyEntropySecret('src/components/Button.js'), false);
    });
  });

  describe('Function Detection', () => {
    it('should detect standard JS functions', () => {
      const code = `
        function hello() { return "world"; }
        const arrow = (x) => x * 2;
        async function fetcher(url) { return await fetch(url); }
      `;
      const funcs = detectFunctions(code);
      const names = funcs.map(f => f.name);
      assert.ok(names.includes('hello'));
      assert.ok(names.includes('arrow'));
      assert.ok(names.includes('fetcher'));
    });

    it('should detect Python functions', () => {
      const code = `def calculate_risk(params):\n    return 100`;
      const funcs = detectFunctions(code);
      const names = funcs.map(f => f.name);
      assert.ok(names.includes('calculate_risk'));
    });
  });

  describe('Diff Logic', () => {
    it('should correctly identify additions and deletions', () => {
      const before = 'line1\nline2\nline3';
      const after = 'line1\nline2.5\nline3\nline4';
      const diff = diffLines(before, after);
      
      assert.strictEqual(diff.addedLineNumbers.length, 2);
      assert.strictEqual(diff.deletedLineNumbers.length, 1);
    });
  });
});
