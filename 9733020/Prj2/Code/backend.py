import json
import smtplib
from smtplib import SMTPResponseException
from email.mime.text import MIMEText
from orm import *
from flask import Flask, request, Response

web_orm = ORM("web")
app = Flask(__name__)


mail_address = ""
mail_password = ""


def read_auth_file():
    global auth_file
    with open("./auth.json") as file:
        auth_file = json.load(file)


def is_auth_valid(authorization):
    for entry in auth_file:
        if entry["username"] == authorization["username"] and entry["password"] == authorization["password"]:
            return True
    return False


def read_mail_password():
    global mail_password
    global mail_address
    with open("./mail.json") as file:
        json_dict = json.load(file)
        mail_address = json_dict["mail"]
        mail_password = json_dict["password"]


def send_mail(receiver_address, mail_content):
    try:
        message = MIMEText(mail_content)
        message['From'] = mail_address
        message['To'] = receiver_address
        message['Subject'] = 'Web project mail'
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(mail_address, mail_password)
            smtp.sendmail(mail_address, receiver_address, message.as_string())
            return "success"
    except SMTPResponseException as e:
        error_code = e.smtp_code
        error_message = e.smtp_error
        return str(error_code) + " " + str(error_message)


# ~~~~~~~~~~~~~~~~~~ Routes ~~~~~~~~~~~~~~~~~~ #

# ~~~~~~~~~~~~~~~~~~ Class ~~~~~~~~~~~~~~~~~~~ #


@app.route('/classes', methods=["Get"])
def get_all_classes():
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    classrooms = web_orm.get_all_data(Classroom)
    return Response(classrooms.to_json(), status=200)


@app.route('/classes/<iid>', methods=["Get"])
def get_class(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    classroom = web_orm.get_data(Classroom, iid)
    if classroom is not None:
        return Response(classroom.to_json(), status=200)
    else:
        return Response("Class not found", status=404)


@app.route('/classes/<iid>/students', methods=["Get"])
def get_class_students(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    classroom = web_orm.get_data(Classroom, iid)
    if classroom is not None:
        students = web_orm.get_all_data(Student)
        students_list = []
        for student in students:
            if student.classroom == classroom:
                student_dict = json.loads(student.to_json())
                students_list.append(student_dict)
        return Response(json.dumps(students_list), status=200)
    else:
        return Response("Class not found", status=404)


@app.route('/classes', methods=["Post"])
def create_class():
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    kwargs = json.loads(request.data.decode())
    classroom = web_orm.create_data(Classroom, kwargs)
    if classroom is not None:
        return Response(classroom.to_json(), status=201)
    else:
        return Response("Bad inputs", status=400)


@app.route('/classes/<iid>', methods=["Put"])
def update_class(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    kwargs = json.loads(request.data.decode())
    classroom = web_orm.update_date(Classroom, iid, kwargs)
    if classroom is not None:
        return Response(classroom.to_json(), status=200)
    else:
        return Response("Bad inputs", status=400)


@app.route('/classes/<iid>', methods=["Delete"])
def delete_class(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    classroom = web_orm.delete_data(Classroom, iid)
    if classroom is not None:
        return Response(classroom.to_json(), status=200)
    else:
        return Response("Class not found", status=404)


# ~~~~~~~~~~~~~~~~~~ Student ~~~~~~~~~~~~~~~~~~~ #


@app.route('/students', methods=["Get"])
def get_all_students():
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    students = web_orm.get_all_data(Student)
    return Response(students.to_json(), status=200)


@app.route('/students/<iid>', methods=["Get"])
def get_student(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    student = web_orm.get_data(Student, iid)
    if student is not None:
        return Response(student.to_json(), status=200)
    else:
        return Response("Student not found", status=404)


@app.route('/students', methods=["Post"])
def create_student():
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    kwargs = json.loads(request.data.decode())
    student = web_orm.create_data(Student, kwargs)
    if student is not None:
        return Response(student.to_json(), status=200)
    else:
        return Response("Bad inputs", status=400)


@app.route('/students/<iid>', methods=["PUT"])
def update_student(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    kwargs = json.loads(request.data.decode())
    student = web_orm.update_date(Student, iid, kwargs)
    if student is not None:
        return Response(student.to_json(), status=200)
    else:
        return Response("Student not found", status=404)


@app.route('/students/<iid>', methods=["Delete"])
def delete_student(iid):
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    iid = int(iid)
    student = web_orm.delete_data(Student, iid)
    if student is not None:
        return Response(student.to_json(), status=200)
    else:
        return Response("Student not found", status=404)


# ~~~~~~~~~~~~~~~~~~ Mail ~~~~~~~~~~~~~~~~~~~ #


@app.route('/mail/send', methods=["Post"])
def send_mail_route():
    if is_auth_valid(request.authorization) is not True:
        return Response("UNAUTHORIZED", status=401)
    arguments = request.args
    if "class_id" in arguments:
        classroom = web_orm.get_data(Classroom, int(arguments["class_id"]))
        if classroom is not None:
            students = web_orm.get_all_data(Student)
            students_list = []
            responses = {}
            for student in students:
                if student.classroom == classroom:
                    students_list.append(student)
                    mail_content = "Student.name: {}, Student.score: {} Classroom.name: {}, Classroom.teacher: {}"\
                        .format(student.name, student.score, classroom.course, classroom.teacher)
                    response = send_mail(student.email, mail_content)
                    responses[student.email] = response
            return Response(json.dumps(responses), status=200)
        else:
            return Response("Class not found", status=404)
    else:
        return Response("Bad inputs", status=400)


if __name__ == "__main__":
    read_auth_file()
    read_mail_password()
    app.run(host='localhost', port=8000)

