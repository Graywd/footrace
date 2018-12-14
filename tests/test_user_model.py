import unittest
import time
from datetime import datetime
from flask import current_app
from app import create_app, db
from app.models import User, AnonymousUser, Role, Permission


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        Role.insert_roles()

    def tearDown(self):
        db_name = current_app.config['MONGODB_SETTINGS']['DB']
        db.connection.drop_database(db_name)
        self.app_context.pop()

    def test_password_setter(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_salts_are_random(self):
        u1 = User(username='cat', email='john@example.com')
        u2 = User(username='dog', email='susan@example.org')
        u1.password = 'cat'
        u2.password = 'dog'
        self.assertTrue(u1.password_hash != u2.password_hash)

    def test_valid_confirmation_token(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):
        u1 = User(username='cat', email='john@example.com')
        u2 = User(username='dog', email='susan@example.org')
        u1.password = 'cat'
        u2.password = 'dog'
        u1.save()
        u2.save()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmation_token(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))

    def test_valid_reset_token(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        token = u.generate_reset_token()
        self.assertTrue(User.reset_password(token, 'dog'))
        u = User.objects(username='cat')[0]
        self.assertTrue(u.verify_password('dog'))

    def test_invalid_reset_token(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        token = u.generate_reset_token()
        self.assertFalse(User.reset_password(token + 'a', 'horse'))
        self.assertTrue(u.verify_password('cat'))

    def test_valid_email_change_token(self):
        u = User(email='john@example.com')
        u.password = 'cat'
        u.save()
        token = u.generate_email_change_token('susan@example.org')
        self.assertTrue(u.change_email(token))
        self.assertTrue(u.email == 'susan@example.org')

    def test_invalid_email_change_token(self):
        u1 = User(username='cat', email='john@example.com')
        u2 = User(username='dog', email='susan@example.org')
        u1.password = 'cat'
        u2.password = 'dog'
        u1.save()
        u2.save()
        token = u1.generate_email_change_token('david@example.net')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'susan@example.org')

    def test_duplicate_email_change_token(self):
        u1 = User(username='cat', email='john@example.com')
        u2 = User(username='dog', email='susan@example.org')
        u1.password = 'cat'
        u2.password = 'dog'
        u1.save()
        u2.save()
        token = u2.generate_email_change_token('john@example.com')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'susan@example.org')

    def test_user_role(self):
        u = User(email='john@example.com')
        u.password = 'cat'
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_moderator_role(self):
        r = Role.objects(name='Moderator').first()
        u = User(email='john@example.com', role=r)
        u.password = 'cat'
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertTrue(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_administrator_role(self):
        r = Role.objects(name='Administrator').first()
        u = User(email='john@example.com', role=r)
        u.password = 'cat'
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertTrue(u.can(Permission.MODERATE))
        self.assertTrue(u.can(Permission.ADMIN))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))
        self.assertFalse(u.can(Permission.COMMENT))
        self.assertFalse(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_timestamps(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        self.assertTrue(
            (datetime.utcnow() - u.member_since).total_seconds() < 3)
        self.assertTrue(
            (datetime.utcnow() - u.last_seen).total_seconds() < 3)

    def test_ping(self):
        u = User(username='cat', email='john@example.com')
        u.password = 'cat'
        u.save()
        time.sleep(2)
        last_seen_before = u.last_seen
        u.ping()
        self.assertTrue(u.last_seen > last_seen_before)

    def test_gravatar(self):
        u = User(email='john@example.com')
        u.password = 'cat'
        with self.app.test_request_context('/'):
            gravatar = u.gravatar()
            gravatar_256 = u.gravatar(size=256)
            gravatar_pg = u.gravatar(rating='pg')
            gravatar_retro = u.gravatar(default='retro')
        self.assertTrue('https://secure.gravatar.com/avatar/' +
                        'd4c74594d841139328695756648b6bd6'in gravatar)
        self.assertTrue('s=256' in gravatar_256)
        self.assertTrue('r=pg' in gravatar_pg)
        self.assertTrue('d=retro' in gravatar_retro)
