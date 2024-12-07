from src.repositories.reference_repo import ReferenceRepository
from src.repositories.user_repo import UserRepository
from src.repositories.post_repo import PostRepository
from src.services.exception import ApiException


class ReferenceService:

    @staticmethod
    def get_references_of_target_user(user_id):
        user = UserRepository.get_user_by_id(user_id)
        if user is None:
            raise ApiException("User not found", 404)
        
        return ReferenceRepository.get_references_for_user(user.id)
    
    @staticmethod
    def create_reference_on_post_to_user(author_id, target_user_id, target_post_id):
        author = UserRepository.get_user_by_id(author_id)
        if author is None:
            raise ApiException("Author not found", 404)

        target_user = UserRepository.get_user_by_id(target_user_id)
        if target_user is None:
            raise ApiException("Target user not found", 404)
        
        post = PostRepository.get_post_by_id(target_post_id)
        if post is None:
            raise ApiException("Post not found", 404)

        return ReferenceRepository.create_reference_on_post_to_user(author.id, target_user.id, post.id)
