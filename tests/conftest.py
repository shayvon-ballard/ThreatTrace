import pytest
import sys
import os
import sqlite3
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dashboard')))

@pytest.fixture
def app():
    db_file = tempfile.mktemp(suffix=".db")

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            severity TEXT,
            description TEXT,
            status TEXT DEFAULT 'open'
        )
    ''')
    conn.commit()
    conn.close()

    os.environ["DB_PATH"] = db_file

    import app as flask_module
    flask_module.app.config["TESTING"] = True
    flask_module.DB_PATH = db_file

    yield flask_module.app

    os.unlink(db_file)
    del os.environ["DB_PATH"]

@pytest.fixture
def client(app):
    return app.test_client()