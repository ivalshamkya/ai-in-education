import os
from pymongo import MongoClient

MONGO_URI = os.environ.get('MONGO_URI')

def get_db():
    mongo = MongoClient(MONGO_URI)
    db = mongo['ai_in_education']
       
    return db