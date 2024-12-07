import sys
import logging
from src.app import app

logging.basicConfig(stream=sys.stderr)

if __name__ == "__main__":
    app.run(debug=True)
