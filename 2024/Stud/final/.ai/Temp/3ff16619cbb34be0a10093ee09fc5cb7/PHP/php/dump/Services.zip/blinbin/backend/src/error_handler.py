import logging
from typing import Dict, List
from src.services.exception import ApiException

import marshmallow.exceptions as marshmallow_exceptions
from flask import jsonify
from werkzeug.exceptions import HTTPException, NotFound
from src.config import Config

logger = logging.getLogger(__name__)


def setup_error_handler(app) -> None:
    """
    Function that will register all the specified error handlers for the app
    """

    def create_error_response(error_message, status_code: int = 400, data=None):

        # Remove the default 404 not found message if it exists
        if not isinstance(error_message, Dict):
            error_message = error_message.replace("404 Not Found: ", '')

        response = jsonify({
            "message": error_message,
            "status_code": status_code,
            "data": data
            })
        response.status_code = status_code
        return response

    def format_marshmallow_validation_error(errors: Dict):
        errors_message = {}

        for key in errors:

            if isinstance(errors[key], Dict):
                errors_message[key] = \
                    format_marshmallow_validation_error(errors[key])

            if isinstance(errors[key], List):
                errors_message[key] = errors[key][0].lower()
        return errors_message

    def error_handler(error):
        logger.error("exception of type {} occurred".format(type(error)))
        if Config.LOG_LEVEL == 'DEBUG':
            logger.exception(error)

        if isinstance(error, HTTPException):
            return create_error_response(str(error), error.code)
        elif isinstance(error, marshmallow_exceptions.ValidationError):
            error_message = format_marshmallow_validation_error(error.messages)
            return create_error_response("Validation error",data=error_message)
        elif isinstance(error, ApiException):
            return create_error_response(
                error.error_message, error.status_code
            )
        else:
            # Internal error happened that was unknown
            return "Internal server error", 500

    app.errorhandler(Exception)(error_handler)
    return app