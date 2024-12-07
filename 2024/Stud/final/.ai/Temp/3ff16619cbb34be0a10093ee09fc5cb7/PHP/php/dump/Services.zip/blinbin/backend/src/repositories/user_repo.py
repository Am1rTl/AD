from src.models.user import User
from src.extensions import db


class UserRepository:
    @staticmethod
    def get_user_by_id(user_id):
        return User.query.get(user_id)
    
    @staticmethod
    def get_all_users():
        return User.query.all()

    @staticmethod
    def get_by_username(name):
        return User.query.filter(User.name == name).first()

    @staticmethod
    def create_user(name, password):
        new_user = User(name=name, password=password)
        db.session.add(new_user)
        db.session.commit()
        return new_user
