import logging
from src.create_app import create_app
from src.config import Config


logger = logging.getLogger(__name__)
app = create_app(Config)

if __name__ == '__main__':
    app.run(debug=True)