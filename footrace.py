import os
from app import create_app
from app import db
from app.models import User
from app.email import send_email
app = create_app(os.getenv('FLASK_CONFIG') or 'default')


@app.shell_context_processor
def make_shell_context():
	return dict(db=db, User=User, send_email=send_email)

if __name__ == "__main__":
	app.run()