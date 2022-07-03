from mongoengine import *


class Classroom(Document):
    iid = IntField(required=True, unique=True)
    course = StringField(required=True)
    teacher = StringField(required=True)


class Student(Document):
    iid = IntField(required=True, unique=True)
    name = StringField(required=True)
    email = EmailField(required=True)
    score = IntField(min_value=0, max_value=20)
    classroom = ReferenceField(Classroom)


class ORM:
    def __init__(self, database_name):
        self.database_name = database_name
        connect(database_name)

    def get_all_data(self, model):
        return model.objects()

    def get_data(self, model, id):
        for data in model.objects():
            if data.iid == id:
                return data
        return None

    def update_date(self, model, id, kwargs):
        try:
            for data in model.objects:
                    if data.iid == id:
                        for key, value in kwargs.items():
                            data[key] = value
                        data.save()
                        return data
        except Exception as e:
            return None
        return None

    def delete_data(self, model, id):
        for data in model.objects():
            if data.iid == id:
                data.delete()
                return data
        return None

    def create_data(self, model, kwargs):
        try:
            if model == Classroom:
                if len(kwargs) != 3:
                    return None
                else:
                    classroom = Classroom(iid=kwargs["iid"], course=kwargs["course"], teacher=kwargs["teacher"])
                    classroom.save()
                    return classroom
            elif model == Student:
                if len(kwargs) != 5:
                    return None
                else:
                    classroom = None
                    for data in Classroom.objects:
                        if data.iid == kwargs["class_id"]:
                            classroom = data
                    student = Student(iid=kwargs["iid"], name=kwargs["name"], email=kwargs["email"],
                                      score=kwargs["score"], classroom=classroom)
                    student.save()
                    return student
        except Exception as e:
            return None
        return None


if __name__ == "__main__":
    web_orm = ORM("web")
    print(web_orm.get_data(Classroom, 1))
    # web_orm.create_data(Classroom, iid=1, course="web", teacher="Mr. Alvani")
    # print(web_orm.create_data(Student, iid=1, name="ali", email="abc@gmail.com", score=19, classroom_id=1))
    # web_orm.update_date(Student, 1, score=12)
    # web_orm.delete_data(Student, 1)
