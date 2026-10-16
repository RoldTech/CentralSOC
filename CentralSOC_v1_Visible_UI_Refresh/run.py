"""Development entry point: ``python run.py``. For production use a WSGI server (gunicorn/waitress)
pointed at ``regexsoc.web:create_app`` and put it behind a TLS-terminating reverse proxy.
"""

import os

from regexsoc.web import create_app

app = create_app()

if __name__ == "__main__":
    if not os.environ.get("REGEXSOC_ENV") == "development":
        print("Refusing to start the built-in dev server outside development. "
              "Set REGEXSOC_ENV=development for local testing, or run this behind a real WSGI server.")
        raise SystemExit(1)
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
