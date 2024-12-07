
from src.models.reference import Reference
from src.extensions import db


class ReferenceRepository:
    
    @staticmethod
    def get_references_for_user(user_id):
        return Reference.query.filter(
            Reference.user_profile_id == user_id,
        ).all()
        
    @staticmethod
    def create_reference_on_post_to_user(author_id, target_user_id, post_id):
        new_reference = Reference(
            user_profile_id=target_user_id,
            author_id=author_id,
            post_id=post_id
        )
        db.session.add(new_reference)
        db.session.commit()
        return new_reference