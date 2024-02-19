import joblib
import requests
import os
import jwt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, jsonify, session, redirect, flash, url_for
from flask_session import Session
from flask_cors import CORS
from flask_pymongo import PyMongo, MongoClient
from flask_bcrypt import Bcrypt
from catboost import CatBoostClassifier

from models.User import User
from db import get_db

SECRET_KEY = os.environ.get('SECRET_KEY')
MONGO_URI = os.environ.get('MONGO_URI')
PORT = os.environ.get('PORT', 7001)
DIR = os.path.dirname(__file__)

REPEATPAPER_MODEL = CatBoostClassifier()
REPEATPAPER_MODEL.load_model(os.path.join(DIR, './predict_model/model_repeat_paper.cb'))
ANATOMY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_anatomy.joblib'))
PHYSIOLOGY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_physiology.joblib'))
BIOCHEMISTRY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_biochemistry.joblib'))
ORALBIOLOGY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_oral_biology.joblib'))
MICROBIOLOGY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_microbiology.joblib'))
PATHOLOGY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_pathology.joblib'))
PHARMACOLOGY_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_pharmacology.joblib'))
DMS_MODEL = joblib.load(os.path.join(DIR, './predict_model/model_dental_material_science.joblib'))

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')

sess = Session()
app.secret_key = SECRET_KEY
app.config['MONGO_URI'] = MONGO_URI
app.config['SESSION_TYPE'] = 'filesystem'
sess.init_app(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

CORS(app)

DB = get_db()

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def is_user_authenticated():
    return current_user.is_authenticated


@app.before_request
def check_authentication():
    if request.endpoint not in ['login', 'register', 'index', 'static'] and not is_user_authenticated():
        return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        id_lecturer = request.form.get('idLecturer')
        name = request.form.get('name')
        password = request.form.get('password')

        users_collection = DB.users
        existing_user = users_collection.find_one({'idLecturer': id_lecturer})

        if existing_user:
            flash("Registration failed. user already exists.", 'error')
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password, 10).decode("utf-8") 

        user_data = {
            'idLecturer': id_lecturer,
            'name': name,
            'password': hashed_password
        }

        try:
            users_collection.insert_one(user_data)
            login_user(User(id_lecturer, name, hashed_password))
            return redirect('/fitur')

        except Exception as e:
            print(e)
            flash("Registration failed. Please try again.", 'error')
            return redirect('/register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        id_lecturer = request.form.get('idLecturer')
        password = request.form.get('password')

        users_collection = DB.users
        user_data = users_collection.find_one({'idLecturer': id_lecturer})

        if user_data and bcrypt.check_password_hash(bytes(user_data['password'], 'utf-8'), password.encode('utf-8')):
            login_user(User(id_lecturer, user_data['name'], user_data['password']))
            return redirect(f"/fitur")
        else:
            flash("Login failed. Invalid credentials.", 'error')
            return redirect('/login')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/profile')
def profile():
    try:
        name = current_user.get_name()
        idLecturer = current_user.get_id()
        return render_template('profile.html', name=name, idLecturer=idLecturer)

    except jwt.ExpiredSignatureError:
        session.clear()
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))

    except jwt.InvalidTokenError:
        session.clear()
        flash('Invalid token. Please log in again.', 'error')
        return redirect(url_for('login'))

@app.route('/grade-result')
def grade_result():
    return render_template('grade-result.html')

@app.route('/fitur')
def fitur():
    if not is_user_authenticated:
        return redirect('/login')
    return render_template('fitur.html')


########################## REPEAT PAPER ######################################

@app.route('/repeat-paper', methods=['GET'])
def repeat_paper():
    return render_template('repeat-paper.html')

@app.route('/repeat-paper/result')
def repeat_paper_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.repeat_paper
        repeat_paper_data = collection.find({"idLecturer": user_id_lecturer})

        return render_template('repeat-paper-result.html', repeat_paper_data=repeat_paper_data)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')

    return render_template('repeat-paper-result.html', repeat_paper_data=None)

@app.route('/repeat-paper/predict', methods=['POST'])
def repeat_paper_predict():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    prediction_result = REPEATPAPER_MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]
    prediction_text = "NO" if prediction_result == 0 else "YES"

    return {'prediction': prediction_text}

@app.route('/repeat-paper/save', methods=['POST'])
def repeat_paper_save():
    data = request.json

    name = data.get('name')
    age = data.get('age')
    total_semesters = data.get('total_semesters')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    result = data.get('result')

    try:
        collection = DB.repeat_paper
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "age": age,
            "total_semesters": total_semesters,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## ANATOMY #######################################

@app.route('/anatomy-mark', methods=['GET'])
def anatomy_mark():
    return render_template('anatomy-mark.html')

@app.route('/anatomy-mark/result', methods=['GET'])
def anatomy_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.anatomy_mark
        anatomy_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('anatomy-result.html', data=anatomy_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('anatomy-result.html', data=None)

@app.route('/anatomy-mark/predict', methods=['POST'])
def anatomy_mark_predict():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    anatomy_result = ANATOMY_MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]

    return {'prediction': anatomy_result}

@app.route('/anatomy-mark/save', methods=['POST'])
def anatomy_mark_save():
    data = request.json

    name = data.get('name')
    age = data.get('age')
    total_semesters = data.get('total_semesters')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    result = data.get('result')

    try:
        collection = DB.anatomy_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "age": age,
            "total_semesters": total_semesters,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## BIOCHEMISTRY #######################################

@app.route('/biochemistry-mark', methods=['GET'])
def biochemistry_mark():
    return render_template('biochemistry-mark.html')

@app.route('/biochemistry-mark/result', methods=['GET'])
def biochemistry_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.biochemistry_mark
        biochemistry_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('biochemistry-result.html', data=biochemistry_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('biochemistry-result.html', data=None)

@app.route('/biochemistry-mark/predict', methods=['POST'])
def biochemistry_mark_predict():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    biochemistry_result = BIOCHEMISTRY_MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]

    return {'prediction': biochemistry_result}

@app.route('/biochemistry-mark/save', methods=['POST'])
def biochemistry_mark_save():
    data = request.json

    name = data.get('name')
    age = data.get('age')
    total_semesters = data.get('total_semesters')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    result = data.get('result')

    try:
        collection = DB.biochemistry_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "age": age,
            "total_semesters": total_semesters,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## PHYSIOLOGY #######################################

@app.route('/physiology-mark', methods=['GET'])
def physiology_mark():
    return render_template('physiology-mark.html')

@app.route('/physiology-mark/result', methods=['GET'])
def physiology_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.physiology_mark
        physiology_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('physiology-result.html', data=physiology_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('physiology-result.html', data=None)

@app.route('/physiology-mark/predict', methods=['POST'])
def physiology_mark_predict():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    physiology_result = PHYSIOLOGY_MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]

    return {'prediction': physiology_result}

@app.route('/physiology-mark/save', methods=['POST'])
def physiology_mark_save():
    data = request.json

    name = data.get('name')
    age = data.get('age')
    total_semesters = data.get('total_semesters')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    result = data.get('result')

    try:
        collection = DB.physiology_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "age": age,
            "total_semesters": total_semesters,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## ORAL BIOLOGY #######################################

@app.route('/oral-biology-mark', methods=['GET'])
def oral_biology_mark():
    return render_template('oralbiology-mark.html')

@app.route('/oral-biology-mark/result', methods=['GET'])
def oral_biology_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.oral_biology_mark
        oral_biology_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('oralbiology-result.html', data=oral_biology_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('oral_biology-result.html', data=None)

@app.route('/oral-biology-mark/predict', methods=['POST'])
def oral_biology_mark_predict():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    oral_biology_result = ORALBIOLOGY_MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]
    print(oral_biology_result)
    return {'prediction': oral_biology_result}

@app.route('/oral-biology-mark/save', methods=['POST'])
def oral_biology_mark_save():
    data = request.json

    name = data.get('name')
    age = data.get('age')
    total_semesters = data.get('total_semesters')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    result = data.get('result')

    try:
        collection = DB.oral_biology_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "age": age,
            "total_semesters": total_semesters,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    

########################## PATHOLOGY #######################################

@app.route('/pathology-mark', methods=['GET'])
def pathology_mark():
    return render_template('pathology-mark.html')

@app.route('/pathology-mark/result', methods=['GET'])
def pathology_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.pathology_mark
        pathology_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('pathology-result.html', data=pathology_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('pathology-result.html', data=None)

@app.route('/pathology-mark/predict', methods=['POST'])
def pathology_mark_predict():
    data = request.get_json()  
    final_gpa = float(data['final_gpa'])
    anatomy = int(data['anatomy'])
    biochemistry = int(data['biochemistry'])
    oralbiology = int(data['oralbiology'])

    pathology_result = PATHOLOGY_MODEL.predict([[final_gpa, anatomy, biochemistry, oralbiology]])[0]
    print(pathology_result)
    return {'prediction': pathology_result}

@app.route('/pathology-mark/save', methods=['POST'])
def pathology_mark_save():
    data = request.json

    name = data.get('name')
    final_gpa = data.get('final_gpa')
    anatomy = data.get('anatomy')
    biochemistry = data.get('biochemistry')
    oralbiology = data.get('oralbiology')
    result = data.get('result')

    try:
        collection = DB.pathology_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "final_gpa": final_gpa,
            "anatomy": anatomy,
            "biochemistry": biochemistry,
            "oralbiology": oralbiology,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################


########################## MICROBIOLOGY #######################################

@app.route('/microbiology-mark', methods=['GET'])
def microbiology_mark():
    return render_template('microbiology-mark.html')

@app.route('/microbiology-mark/result', methods=['GET'])
def microbiology_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.microbiology_mark
        microbiology_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('microbiology-result.html', data=microbiology_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('microbiology-result.html', data=None)

@app.route('/microbiology-mark/predict', methods=['POST'])
def microbiology_mark_predict():
    data = request.get_json()  
    anatomy = int(data['anatomy'])
    physiology = int(data['physiology'])
    biochemistry = int(data['biochemistry'])
    oralbiology = int(data['oralbiology'])

    microbiology_result = MICROBIOLOGY_MODEL.predict([[anatomy, physiology, biochemistry, oralbiology]])[0]
    print(microbiology_result)
    return {'prediction': microbiology_result}

@app.route('/microbiology-mark/save', methods=['POST'])
def microbiology_mark_save():
    data = request.json

    name = data.get('name')
    anatomy = data.get('anatomy')
    physiology = data.get('physiology')
    biochemistry = data.get('biochemistry')
    oralbiology = data.get('oralbiology')
    result = data.get('result')

    try:
        collection = DB.microbiology_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "anatomy": anatomy,
            "physiology": physiology,
            "biochemistry": biochemistry,
            "oralbiology": oralbiology,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## PHARMACOLOGY #######################################

@app.route('/pharmacology-mark', methods=['GET'])
def pharmacology_mark():
    return render_template('pharmacology-mark.html')

@app.route('/pharmacology-mark/result', methods=['GET'])
def pharmacology_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.pharmacology_mark
        pharmacology_mark = collection.find({"idLecturer": user_id_lecturer})

        return render_template('pharmacology-result.html', data=pharmacology_mark)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('pharmacology-result.html', data=None)

@app.route('/pharmacology-mark/predict', methods=['POST'])
def pharmacology_mark_predict():
    data = request.get_json()  
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])
    anatomy = int(data['anatomy'])
    oralbiology = int(data['oralbiology'])

    pharmacology_result = PHARMACOLOGY_MODEL.predict([[average_gpa, final_gpa, anatomy, oralbiology]])[0]
    print(pharmacology_result)
    return {'prediction': pharmacology_result}

@app.route('/pharmacology-mark/save', methods=['POST'])
def pharmacology_mark_save():
    data = request.json

    name = data.get('name')
    average_gpa = data.get('average_gpa')
    final_gpa = data.get('final_gpa')
    anatomy = data.get('anatomy')
    oralbiology = data.get('oralbiology')
    result = data.get('result')

    try:
        collection = DB.pharmacology_mark
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "average_gpa": average_gpa,
            "final_gpa": final_gpa,
            "anatomy": anatomy,
            "oralbiology": oralbiology,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
    
########################## DENTAL MATERIAL SCIENCE #######################################

@app.route('/dental-material-science', methods=['GET'])
def dental_material_science():
    return render_template('dental-material-science.html')

@app.route('/dental-material-science/result', methods=['GET'])
def dental_material_science_result():
    user_id_lecturer = current_user.get_id()

    try:
        collection = DB.dental_material_science
        dental_material_science = collection.find({"idLecturer": user_id_lecturer})

        return render_template('dental-material-science-result.html', data=dental_material_science)
    except Exception as e:
        print(e)
        flash("Error fetching repeat paper data.", 'error')
    return render_template('dental-material-science-result.html', data=None)

@app.route('/dental-material-science/predict', methods=['POST'])
def dental_material_science_predict():
    data = request.get_json()  
    anatomy = int(data['anatomy'])
    physiology = int(data['physiology'])
    biochemistry = int(data['biochemistry'])
    oralbiology = int(data['oralbiology'])

    dental_material_science_result = DMS_MODEL.predict([[anatomy, physiology, biochemistry, oralbiology]])[0]
    print(dental_material_science_result)
    return {'prediction': dental_material_science_result}

@app.route('/dental-material-science/save', methods=['POST'])
def dental_material_science_save():
    data = request.json

    name = data.get('name')
    anatomy = data.get('anatomy')
    physiology = data.get('physiology')
    biochemistry = data.get('biochemistry')
    oralbiology = data.get('oralbiology')
    result = data.get('result')

    try:
        collection = DB.dental_material_science
        new_data = {
            "idLecturer": current_user.get_id(),
            "name": name,
            "anatomy": anatomy,
            "physiology": physiology,
            "biochemistry": biochemistry,
            "oralbiology": oralbiology,
            "result": result,
        }
        collection.insert_one(new_data)

        return jsonify({"message": "Success, data created"}), 201
    except Exception as e:
        print("error:" + str(e))
        return jsonify({"message": str(e)}), 400

##########################################################################
 
if __name__ == '__main__':
    app.run(debug=True, port=PORT)
