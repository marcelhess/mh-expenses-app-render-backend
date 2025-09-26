import request from 'supertest';
import app from '../../src/app.js';
import User from '../../src/models/User.js';
import { createTestUser, generateJWT } from '../utils/testHelpers.js';
import { connectTestDB, clearTestDB, disconnectTestDB } from '../setup/testDb.js';

describe('Auth Integration Tests', () => {
  beforeAll(async () => {
    await connectTestDB();
  });

  beforeEach(async () => {
    await clearTestDB();
  });

  afterAll(async () => {
    await disconnectTestDB();
  });
  describe('POST /api/v1/auth/register', () => {
    test('should register a new user successfully', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        password: 'Password123!',
        phone: '+233123456789'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeDefined();
      expect(response.body.user).toBeDefined();
      expect(response.body.data.user).toHaveProperty('id');
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.user.name).toBe(userData.name);
      expect(response.body.data.user).not.toHaveProperty('password');

      // Verify user was created in database
      const user = await User.findById(response.body.data.user.id);
      expect(user).toBeTruthy();
      expect(user.email).toBe(userData.email);
    });

    test('should not register user with invalid email', async () => {
      const userData = {
        name: 'John Doe',
        email: 'invalid-email',
        password: 'Password123!',
        phone: '+233123456789'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('email');
    });

    test('should not register user with weak password', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        password: '123', // weak password
        phone: '+233123456789'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('New password must be at least 6 characters');
    });

    test('should not register user with duplicate email', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        password: 'Password123!',
        phone: '+233123456789'
      };

      // Create first user
      await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      // Try to create second user with same email
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...userData,
          name: 'Jane Doe',
          phone: '+233987654321'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('duplicate');
    });

    test('should not register user with missing required fields', async () => {
      const userData = {
        email: 'john.doe@example.com',
        password: 'Password123!'
        // missing name and phone
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/v1/auth/login', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await createTestUser();
    });

    test('should login user with valid credentials', async () => {
      const loginData = {
        email: testUser.email,
        password: 'Password123!'
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeDefined();
      expect(response.body.user).toBeDefined();
      expect(response.body.data.user).toHaveProperty('id');
      expect(response.body.data.user.email).toBe(testUser.email);
      expect(response.body.data.user).not.toHaveProperty('password');
    });

    test('should not login user with invalid email', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'Password123!'
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });

    test('should not login user with invalid password', async () => {
      const loginData = {
        email: testUser.email,
        password: 'WrongPassword123!'
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });

    test('should not login inactive user', async () => {
      // Update user to inactive status
      await User.findByIdAndUpdate(testUser._id, { status: 'inactive' });

      const loginData = {
        email: testUser.email,
        password: 'Password123!'
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('account is inactive');
    });

    test('should not login with missing credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/v1/auth/me', () => {
    let testUser;
    let authToken;

    beforeEach(async () => {
      testUser = await createTestUser();
      authToken = generateJWT(testUser._id);
    });

    test('should get current user profile with valid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data._id).toBe(testUser._id.toString());
      expect(response.body.data.email).toBe(testUser.email);
      expect(response.body.data.name).toBe(testUser.name);
      expect(response.body.data).not.toHaveProperty('password');
    });

    test('should not get profile without token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('Not authorized');
    });

    test('should not get profile with invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('Not authorized');
    });
  });

  describe('GET /api/v1/auth/logout', () => {
    let testUser;
    let authToken;

    beforeEach(async () => {
      testUser = await createTestUser();
      authToken = generateJWT(testUser._id);
    });

    test('should logout user successfully', async () => {
      const response = await request(app)
        .get('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual({});
    });

    test('should not logout without token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/logout')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('Not authorized');
    });
  });

  describe('PUT /api/v1/auth/updateprofile', () => {
    let testUser;
    let authToken;

    beforeEach(async () => {
      testUser = await createTestUser();
      authToken = generateJWT(testUser._id);
    });

    test('should update user profile successfully', async () => {
      const updateData = {
        name: 'Updated Name',
        email: 'updated@example.com'
      };

      const response = await request(app)
        .put('/api/v1/auth/updateprofile')
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe(updateData.name);
      expect(response.body.data.email).toBe(updateData.email);

      // Verify update in database
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.name).toBe(updateData.name);
      expect(updatedUser.email).toBe(updateData.email);
    });

    test('should not update profile with invalid email', async () => {
      const updateData = {
        email: 'invalid-email'
      };

      const response = await request(app)
        .put('/api/v1/auth/updateprofile')
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('email');
    });

    test('should not update profile without token', async () => {
      const updateData = {
        name: 'Updated Name'
      };

      const response = await request(app)
        .put('/api/v1/auth/updateprofile')
        .send(updateData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('Not authorized');
    });
  });

  describe('PUT /api/v1/auth/updatepassword', () => {
    let testUser;
    let authToken;

    beforeEach(async () => {
      testUser = await createTestUser();
      authToken = generateJWT(testUser._id);
    });

    test('should update password successfully', async () => {
      const passwordData = {
        currentPassword: 'password123',
        newPassword: 'NewPassword123!'
      };

      const response = await request(app)
        .put('/api/v1/auth/updatepassword')
        .set('Authorization', `Bearer ${authToken}`)
        .send(passwordData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeDefined();
      expect(response.body.user).toBeDefined();

      // Verify password was updated by trying to login with new password
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: passwordData.newPassword
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);
    });

    test('should not update password with wrong current password', async () => {
      const passwordData = {
        currentPassword: 'WrongPassword123!',
        newPassword: 'NewPassword123!'
      };

      const response = await request(app)
        .put('/api/v1/auth/updatepassword')
        .set('Authorization', `Bearer ${authToken}`)
        .send(passwordData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Password is incorrect');
    });

    test('should not update password with weak new password', async () => {
      const passwordData = {
        currentPassword: 'password123',
        newPassword: '123' // weak password
      };

      const response = await request(app)
        .put('/api/v1/auth/updatepassword')
        .set('Authorization', `Bearer ${authToken}`)
        .send(passwordData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('New password must be at least 6 characters');
    });

    test('should not update password without token', async () => {
      const passwordData = {
        currentPassword: 'password123',
        newPassword: 'NewPassword123!'
      };

      const response = await request(app)
        .put('/api/v1/auth/updatepassword')
        .send(passwordData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error || response.body.message).toContain('Not authorized');
    });
  });

  describe('POST /api/v1/auth/forgotpassword', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await createTestUser();
    });

    test('should send password reset email for valid user', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgotpassword')
        .send({ email: testUser.email })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Email sent');

      // Verify reset token was set in database
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.resetPasswordToken).toBeDefined();
      expect(updatedUser.resetPasswordExpire).toBeDefined();
    });

    test('should return error for non-existent email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgotpassword')
        .send({ email: 'nonexistent@example.com' })
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('There is no user with that email');
    });

    test('should not accept invalid email format', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgotpassword')
        .send({ email: 'invalid-email' })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('email');
    });
  });

  describe('PUT /api/v1/auth/resetpassword/:resettoken', () => {
    let testUser;
    let resetToken;

    beforeEach(async () => {
      testUser = await createTestUser();
      
      // Generate reset token
      resetToken = testUser.getResetPasswordToken();
      await testUser.save();
    });

    test('should reset password with valid token', async () => {
      const newPassword = 'NewPassword123!';

      const response = await request(app)
        .put(`/api/v1/auth/resetpassword/${resetToken}`)
        .send({ password: newPassword })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Password reset successful');

      // Verify password was reset by trying to login with new password
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: newPassword
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);

      // Verify reset token was cleared
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.resetPasswordToken).toBeUndefined();
      expect(updatedUser.resetPasswordExpire).toBeUndefined();
    });

    test('should not reset password with invalid token', async () => {
      const response = await request(app)
        .put('/api/v1/auth/resetpassword/invalid-token')
        .send({ password: 'NewPassword123!' })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid or expired token');
    });

    test('should not reset password with weak password', async () => {
      const response = await request(app)
        .put(`/api/v1/auth/resetpassword/${resetToken}`)
        .send({ password: '123' }) // weak password
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Password must be at least 6 characters');
    });
  });
});