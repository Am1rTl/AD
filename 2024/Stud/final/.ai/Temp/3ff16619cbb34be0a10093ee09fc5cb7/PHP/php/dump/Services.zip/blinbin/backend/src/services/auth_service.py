from src.services.exception import ApiException
from src.repositories.user_repo import UserRepository
from werkzeug.security import generate_password_hash, check_password_hash
from string import printable


class AuthService:

    @staticmethod
    def _hash_password(password):
        # Generate a hashed password
        return generate_password_hash(password)

    @staticmethod
    def _verify_password(input_password, stored_hashed_password):
        # Verify if the entered password matches the stored hash
        return check_password_hash(stored_hashed_password, input_password)

    @staticmethod
    def signup_user(name, password):
        if UserRepository.get_by_username(name):
            raise ApiException(f"User with name '{name}' already exists", 409)
    
        if set(name).difference(printable):
            raise ApiException("Title can not contain special characters", 400)

        hashed_password = AuthService._hash_password(password)
        return UserRepository.create_user(name, hashed_password)

    @staticmethod
    def authenticate_user(name, password):
        user = UserRepository.get_by_username(name)
        if not user:
            raise ApiException(f"Invalid username or password", 401)

        # Verify the password
        if not AuthService._verify_password(password, user.password):
            raise ApiException(f"Invalid username or password", 401)

        return user
