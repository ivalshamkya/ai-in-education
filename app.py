import joblib
import requests
import os
from flask import Flask, render_template, request, jsonify, session, redirect, flash, url_for
from flask_session import Session
from catboost import CatBoostClassifier
from flask_cors import CORS
import jwt
from flask_pymongo import PyMongo, MongoClient
import bcrypt

SECRET_KEY = os.environ.get('SECRET_KEY')
MONGO_URI = os.environ.get('MONGO_URI')
PORT = os.environ.get('PORT', 7001)
DIR = os.path.dirname(__file__)

MODEL = CatBoostClassifier()
MODEL.load_model(os.path.join(DIR, './predict_model/model_repeat_paper.cb'))
MODEL2 = joblib.load(os.path.join(DIR, './predict_model/model_anatomy.joblib'))
MODEL3 = joblib.load(os.path.join(DIR, './predict_model/model_physiology.joblib'))

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')

sess = Session()
app.secret_key = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['MONGO_URI'] = MONGO_URI

mongo = MongoClient(MONGO_URI)
db = mongo['test']

sess.init_app(app)
CORS(app)

def is_user_authenticated():
    return 'user' in session

@app.before_request
def check_authentication():
    if request.endpoint not in ['login', 'register', 'index', 'static'] and not is_user_authenticated():
        return redirect('/login')

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

        # Check if idLecturer already exists
        users_collection = db.users
        existing_user = users_collection.find_one({'idLecturer': id_lecturer})

        if existing_user:
            flash("Registration failed. user already exists.", 'error')
            return redirect('/register')

        hashed_password = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt()).decode("utf-8") 

        user_data = {
            'idLecturer': id_lecturer,
            'name': name,
            'password': hashed_password
        }

        try:
            users_collection.insert_one(user_data)
            session['users'] = user_data
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

        users_collection = db.users
        user_data = users_collection.find_one({'idLecturer': id_lecturer})

        if user_data and bcrypt.checkpw(password.encode('utf-8'), bytes(user_data['password'], 'utf-8')):
            session['user'] = user_data
            return redirect(f"/fitur?id={id_lecturer}")
        else:
            flash("Login failed. Invalid credentials.", 'error')
            return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        name = session.get('name')
        idLecturer = session.get('idLecturer')
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

@app.route('/pathology-mark/result')
def pathology_result():
    return render_template('pathology-result.html')

@app.route('/microbiology-mark/result')
def microbiology_result():
    return render_template('microbiology-result.html')

@app.route('/pharmacology-mark/result')
def pharmacology_result():
    return render_template('pharmacology-result.html')

@app.route('/dental-material-science/result')
def dental_material_science_result():
    return render_template('dental-material-science-result.html')

@app.route('/fitur')
def fitur():
    if not is_user_authenticated:
        return redirect('/login')
    return render_template('fitur.html')

@app.route('/anatomy-mark', methods=['GET'])
def anatomy_mark():
    return render_template('anatomy-mark.html')

@app.route('/anatomy-mark/result', methods=['GET'])
def anatomy_result():
    return render_template('anatomy-result.html')

@app.route('/physiology-mark', methods=['GET'])
def physiology_mark():
    return render_template('physiology-mark.html')

@app.route('/biochemistry-mark', methods=['GET'])
def biochemistry_mark():
    return render_template('biochemistry-mark.html')

@app.route('/oralbiology-mark', methods=['GET'])
def oralbiology_mark():
    return render_template('oralbiology-mark.html')

@app.route('/pathology-mark', methods=['GET'])
def pathology_mark():
    return render_template('pathology-mark.html')

@app.route('/microbiology-mark', methods=['GET'])
def microbiology_mark():
    return render_template('microbiology-mark.html')

@app.route('/pharmacology-mark', methods=['GET'])
def pharmacology_mark():
    return render_template('pharmacology-mark.html')

@app.route('/dental-material-science', methods=['GET'])
def dental_material_science():
    return render_template('dental-material-science.html')

@app.route('/predict/anatomy', methods=['POST'])
def predict_anatomy_route():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    anatomy_result = MODEL2.predict([[age, total_semesters, average_gpa, final_gpa]])[0]

    return {'prediction': anatomy_result}

@app.route('/predict/physiology', methods=['POST'])
def predict_physiology_route():
    data = request.get_json()  
    age = int(data['age'])
    total_semesters = int(data['total_semesters'])
    average_gpa = float(data['average_gpa'])
    final_gpa = float(data['final_gpa'])

    physiology_result = MODEL3.predict([[age, total_semesters, average_gpa, final_gpa]])[0]

    return {'prediction': physiology_result}



########################## REPEAT PAPER ######################################

@app.route('/repeat-paper', methods=['GET'])
def repeat_paper():
    return render_template('repeat-paper.html')

@app.route('/repeat-paper/result')
def repeat_paper_result():
    user_id_lecturer = session.get('user').get('idLecturer')

    try:
        collection = db.repeat_paper
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

    prediction_result = MODEL.predict([[age, total_semesters, average_gpa, final_gpa]])[0]
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
        collection = db.repeat_paper
        new_data = {
            "idLecturer": session['user']['idLecturer'],
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

#######################################################################
 
if __name__ == '__main__':
    app.run(debug=True, port=7001)
