from src.repositories.user_repo import UserRepository
from src.middleware.auth import login_required
from src.services.exception import ApiException


class UserService:

    @staticmethod
    def get_all_users():
        return UserRepository.get_all_users()

    @staticmethod
    def get_user_by_id(user_id):
        user = UserRepository.get_user_by_id(user_id)
        if not user:
            raise ApiException("User not found", 404)
        return user

    @staticmethod
    def get_user_by_id_with_auth(user_id, sess_user_id):

        user = UserRepository.get_user_by_id(user_id)
        if not user:
            raise ApiException("User not found", 404)
        
        # arg 2 if need to cleanup private posts from results
        return user, sess_user_id != user.id
