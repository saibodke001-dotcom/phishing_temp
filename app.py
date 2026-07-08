from app import create_app
from app.utils.logger import logger

app = create_app()

if __name__ == '__main__':
    logger.info("Starting PhishGuard Enterprise Edition...")
    app.run(debug=True, host='0.0.0.0', port=5000)
