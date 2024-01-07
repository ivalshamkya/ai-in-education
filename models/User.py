from db import get_db

class User:
    def __init__(self, idLecturer, name, password):
        self.id = idLecturer
        self.name = name
        self.password = password

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get_name(self):
        return str(self.name)

    @staticmethod
    def get(user_id):
        db = get_db()
        users_collection = db.users
        user_data = users_collection.find_one({'idLecturer': user_id})
        if user_data:
            return User(idLecturer=user_data['idLecturer'], name=user_data['name'], password=user_data['password'])
        return None