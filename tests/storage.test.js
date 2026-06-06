const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const { 
  saveSession, 
  listSessions, 
  getSession,
  openDatabase,
  createSchema,
  setDatabase
} = require('../backend/storage.ts');

describe('Storage Logic', () => {
  beforeEach(() => {
    
    const testDb = openDatabase(':memory:');
    createSchema(testDb);
    setDatabase(testDb);
  });

  it('should save and retrieve a session', () => {
    const session = {
      id: 'test-session-' + Math.random().toString(16).slice(2),
      name: 'test.trace',
      project: 'test-project',
      riskScore: 42,
      metrics: { files: 1, commands: 0 },
      events: [],
      snapshots: [],
      fileDiffs: []
    };

    saveSession(session);
    
    const sessions = listSessions();
    assert.ok(sessions.length >= 1);
    
    const saved = getSession(session.id);
    assert.strictEqual(saved.id, session.id);
    assert.strictEqual(saved.riskScore, 42);
  });

  it('should return null for non-existent session', () => {
    const session = getSession('does-not-exist');
    assert.strictEqual(session, null);
  });
});
