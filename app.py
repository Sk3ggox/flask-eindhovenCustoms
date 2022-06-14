import os
from flask import Flask, redirect, render_template, request, render_template_string, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_user import current_user, login_required, roles_required, UserManager, UserMixin
from flask_wtf import FlaskForm
from wtforms import IntegerField, SelectField, BooleanField, PasswordField, StringField, SubmitField, HiddenField
from wtforms.validators import ValidationError
from flask_babelex import Babel
from datetime import datetime

class ConfigClass(object):
    #Flask Settings
    SECRET_KEY = str(os.urandom(69))
    #For prod enable ^, down is for debugging
    #SECRET_KEY='secret'

    #Flask-SQLAlchemy Settings
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://yes:yes@localhost:3306/eindhovencustoms'   #File-based SQL DB
    SQLALCHEMY_TRACK_MODIFICATIONS = False              #Avoid SQLAlchemy warning

    #Flask-User Settings
    USER_APP_NAME = "Flask application"                 #Show in templates and footers
    USER_ENABLE_EMAIL = False                           #Disable email auth
    USER_ENABLE_USERNAME = True                         #Enable username auth
    USER_REQUIRE_RETYPE_PASSWORD = False                #Simple register form\

def create_app():
    """Flask application factory"""

    #Create Flask app and load app.conf
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')

    #Init Flask-SQLAlchemy
    db = SQLAlchemy(app)

    #Init Flask-Babelex
    babel = Babel(app)

    # Def item model
    class Items(db.Model):
        __tablename__ = 'item_table'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100, collation='utf8_bin'), nullable=False)
        oem = db.Column(db.String(100, collation='utf8_bin'), nullable=False)
        amount = db.Column(db.Integer, nullable=False)
        minamount = db.Column(db.Integer, nullable=False)

    ##Def user-data model
    class User(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer(), unique=True, primary_key=True)
        active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')
        #User auth info
        username = db.Column(db.String(100, collation='utf8_bin'), nullable=False, server_default='1')
        password = db.Column(db.String(255), nullable=False, server_default='')
        #Define relationship to Role via UserRoles
        roles = db.relationship('Role', secondary='user_roles')

    # Define the Role Data-model
    class Role(db.Model):
        __tablename__ = 'roles'
        id = db.Column(db.Integer(), unique=True, primary_key=True)
        name = db.Column(db.String(50), unique=True)

    #Define UserRoles association table
    class UserRoles(db.Model):
        __tablename__ = 'user_roles'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

    # Define logging table
    class LogTable(db.Model):
        __tablename__='logs'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
        item = db.Column(db.String(100), nullable=False)
        #action = db.Column(db.String(100), nullable=False)
        amount = db.Column(db.Integer(), nullable=False)
        timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)

    #Setup Flask-User and specify User data-model
    user_manager = UserManager(app, db, User)

    #Create all db tables
    db.create_all()

    manager_role = Role(name = 'Manager')
    mechanic_role = Role(name= 'Mechanic')
    admin_role = Role(name= 'Admin')

    # Create sample data, 2 users with different roles, item and log
    if not User.query.filter(User.username == 'mechanic').first():
        user = User(
            username = 'mechanic',
            # This is good for flask-user conf login system, WHICH ALREADY IMPLEMENTS SALTING!!! (dug through flask-user source code to find it...)
            password = user_manager.hash_password('secure')
        )
        user.roles = [mechanic_role,]
        db.session.add(user)
        db.session.commit()

    if not User.query.filter(User.username == 'manager').first():
        user = User(
            username = 'manager',
            password = user_manager.hash_password('secure')
        )
        user.roles = [manager_role,]
        db.session.add(user)
        db.session.commit()

    if not User.query.filter(User.username == 'admin').first():
        user = User(
            username = 'admin',
            password = user_manager.hash_password('secure')
        )
        user.roles = [admin_role,]
        db.session.add(user)
        db.session.commit()

    if not Items.query.filter(Items.name == 'testitem').first():
        item = Items(
            name = 'testitem',
            oem = '609 319 093',
            amount = 24,
            minamount = 30
        )
        db.session.add(item)
        db.session.commit()

    def createLogs():
        if not LogTable.query.filter(LogTable.id == 1).first():
            item = LogTable(
                user_id = 1,
                item = '609 319 093',
                amount = -44,
                timestamp = '2022-06-10 09:06:15'
            )
            db.session.add(item)
            db.session.commit()

        if not LogTable.query.filter(LogTable.id == 2).first():
            item = LogTable(
                user_id = 1,
                item = '609 319 093',
                amount = 45,
                timestamp = '2022-06-11 09:06:15'
            )
            db.session.add(item)
            db.session.commit()

        if not LogTable.query.filter(LogTable.id == 3).first():
            item = LogTable(
                user_id = 1,
                item = '609 319 093',
                amount = 160,
                timestamp = '2022-06-12 09:06:15'
            )
            db.session.add(item)
            db.session.commit()

        if not LogTable.query.filter(LogTable.id == 4).first():
            item = LogTable(
                user_id = 1,
                item = '609 319 093',
                amount = -50,
                timestamp = '2022-06-13 09:06:15'
            )
            db.session.add(item)
            db.session.commit()
    createLogs()

    #Home page accessible to users
    @app.route('/')
    @login_required
    def home_page():
        if current_user.has_roles('Manager'):
            return redirect(url_for('managerpage'))
        elif current_user.has_roles('Mechanic'):
            return redirect(url_for('mechanicpage'))
        elif current_user.has_roles('Admin'):
            return redirect(url_for('adminpage'))
        else:
            return render_template_string("<p>{%trans%}Something went wrong{%endtrans%}</p><br><a href={{ url_for('user.logout') }}>{%trans%}Sign out{%endtrans%}</a>")

    class CRUDUser(FlaskForm):
        id = HiddenField()
        submitedit = SubmitField('Edit')
        submitdel = SubmitField('Delete')

    @app.route('/admin', methods=['GET', 'POST'])
    @roles_required('Admin')
    def adminpage():
        crudform = CRUDUser()
        users = db.session.execute(
                ''' SELECT users.id, users.is_active, users.username, roles.name
                    FROM user_roles
                    INNER JOIN users ON user_roles.user_id = users.id
                    INNER JOIN roles ON user_roles.role_id = roles.id;
                ''').fetchall()
        if crudform.submitdel.data and crudform.validate_on_submit():
            usr = db.session.query(User).filter(User.id==crudform.id.data).one()
            db.session.delete(usr)
            db.session.commit()
            return redirect(url_for('adminpage'))
        if crudform.submitedit.data and crudform.validate_on_submit():
            return redirect(url_for('updateuser', id=crudform.id.data))
        return render_template('admin/admin.html', users=users, crudform=crudform)

    def getChoices():
            choices = []
            rows = db.session.query(Role).count()
            for x in range(rows):
                choices.append(db.session.query(Role.name).filter(Role.id==x+1).one()[0])
            return choices

    class EditUserForm(FlaskForm):
        id = HiddenField()
        active = BooleanField()
        username = StringField()
        role = SelectField(choices=getChoices())
        submitedit = SubmitField('Edit item')

    @app.route('/admin/update/<int:id>', methods=['GET', 'POST'])
    @roles_required('Admin')
    def updateuser(id):
        user = db.session.query(User.id, User.active, User.username, Role.name).filter(User.id == id).join(UserRoles, UserRoles.user_id == User.id).join(Role, Role.id == UserRoles.role_id).first()
        form = EditUserForm()
        if request.method == 'POST':
            if form.submitedit.data and form.validate_on_submit():
                # Update user vars
                db.session.query(User).filter(User.id==id).update({'active':form.active.data, 'username':form.username.data})
                db.session.commit()
                # Update UserRoles table
                new_id = db.session.query(Role.id).filter(Role.name==form.role.data).first()
                db.session.query(UserRoles).filter(UserRoles.user_id==id).update({'role_id':new_id[0]})
                db.session.commit()
                #Redirect to refresh
                return redirect(url_for('updateuser',id=id))
        form.active.data = user.active
        form.username.data = user.username
        form.role.data = user.name
            
        return render_template('admin/update.html',user=user, form=form, id=id)

    class AddNewUserForm(FlaskForm):
        active = BooleanField('Active')
        username = StringField('Username')
        role = SelectField(choices=getChoices())
        password = PasswordField('Password')
        submit = SubmitField('Submit')

    @app.route('/admin/adduser', methods=['GET', 'POST'])
    def adduser():
        form = AddNewUserForm()
        if form.submit.data and form.validate_on_submit():
            if not User.query.filter(User.username == form.username.data).first():
                user = User(
                    username = form.username.data,
                    password = user_manager.hash_password(form.password.data)
                )
            role = Role.query.filter_by(name=form.role.data).one()
            user.roles.append(role)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('adduser', form=form))
        return render_template('admin/adduser.html', form=form)

    class ItemSearchForm(FlaskForm):
        searchitem = StringField('Enter item name')
        submitsearch = SubmitField('Search')

    @app.route('/manager', methods=['GET', 'POST'])
    @roles_required('Manager')
    def managerpage():
        search = None
        form = ItemSearchForm()
        if form.submitsearch.data and form.validate_on_submit():
            return search_results(form.searchitem.data)
        else:
            select_items = db.session.query(Items.name, Items.oem, Items.amount, Items.minamount)
        # Minamount reached check
        query = db.session.query(Items).filter(Items.minamount > Items.amount).all()
        return render_template('manager/manager.html', form=form, select_items=select_items, query=query)

    @app.route('/manager/search')
    @roles_required('Manager')
    def search_results(search):
        form = ItemSearchForm()
        if search == '':
            return redirect(url_for('managerpage'))
        else:
            adapted_search = '%' + search + '%'
            select_items = db.session.execute(
                "SELECT name, oem, amount, minamount FROM item_table WHERE name LIKE :s OR oem LIKE :s",
                {"s": "%" + adapted_search + "%"},
            ).fetchall()
            return render_template('manager/view.html', form=form, select_items=select_items)

    class AddNewItemForm(FlaskForm):
        name = StringField('Item name')
        oem = StringField('Item OEM')
        amount = IntegerField('Item amount')
        minamount = IntegerField('Minimum available item amount')
        submit = SubmitField('Submit')

    @app.route('/manager/add', methods=['GET', 'POST'])
    @roles_required('Manager')
    def manageraddpage():
        form = AddNewItemForm()
        if form.submit.data and form.validate_on_submit():
            if not db.session.query(Items).filter(Items.oem==form.oem.data).first():
                createitem = Items(
                    name = form.name.data,
                    oem = form.oem.data,
                    amount = form.amount.data,
                    minamount = form.minamount.data
                )
                db.session.add(createitem)
                db.session.commit()
                return redirect(url_for('manageraddpage'))
            else:
                raise ValidationError('Item with this OEM number already exists')
        return render_template('manager/addpage.html', form=form)

    class EditItemForm(FlaskForm):
        name = StringField()
        oem = StringField()
        amount = IntegerField()
        minamount = IntegerField()
        submitedit = SubmitField('Edit item')
        submitdelete = SubmitField('Delete item')
        submitstats = SubmitField('View stats')

    @app.route('/manager/options/<oem>', methods=['GET', 'POST'])
    @roles_required('Manager')
    def options(oem):
        editform = EditItemForm()
        clickeditem = db.session.query(Items.id, Items.name, Items.oem, Items.amount, Items.minamount).filter(Items.oem==oem).first()
        if editform.submitdelete.data and editform.validate_on_submit():
            db.session.query(Items).filter(Items.id==clickeditem.id).delete()
            db.session.commit()
            return redirect(url_for('managerpage'))
        elif editform.submitstats.data and editform.validate_on_submit():
            return redirect(url_for('stats', oem=clickeditem.oem))
        elif editform.submitedit.data and editform.validate_on_submit():
            db.session.query(Items).filter(Items.id==clickeditem.id).update({'name':editform.name.data, 'oem':editform.oem.data, 'amount':editform.amount.data, 'minamount':editform.minamount.data})
            db.session.commit()
            return redirect(url_for('options', oem=editform.oem.data))
        else:
            editform.name.data = clickeditem.name
            editform.oem.data = clickeditem.oem
            editform.amount.data = clickeditem.amount
            editform.minamount.data = clickeditem.minamount
            return render_template('manager/options/options.html', clickeditem=clickeditem, editform=editform)

    @app.route('/manager/options/<oem>/stats')
    @roles_required('Manager')
    def stats(oem):
        select_items = db.session.execute(
                "SELECT amount, timestamp FROM logs WHERE item LIKE :s ORDER BY timestamp ASC",
                {"s": oem},
            ).fetchall()

        current_amount = db.session.execute(
            "SELECT amount FROM item_table WHERE oem LIKE :s",
            {"s": oem},
        ).fetchone()
        current_time = datetime.utcnow()

        labels = []    
        values = []

        for i in select_items:
            labels.insert(0,i[1])
            values.insert(0,i[0])  
        labels.insert(0,current_time)
        values.insert(0,current_amount[0])

        amount = []
        counter = 0
        for x in values:
            if x >= 0:
                counter += abs(x)
                amount.append(counter)
            else:
                counter -= abs(x)
                amount.append(counter)

        return render_template('manager/options/stats.html', title="Usage of "+oem,max=100, labels=labels, values=amount)

    class MechChangeAmountForm(FlaskForm):
        oem = HiddenField('')
        amount = IntegerField('')
        remove = SubmitField('Remove')
        add = SubmitField('Add')

    @app.route('/mechanic', methods=['GET', 'POST'])
    @roles_required('Mechanic')
    def mechanicpage():
        search = None
        amount = None
        form = ItemSearchForm()
        addremform = MechChangeAmountForm()

        if form.submitsearch.data and form.validate_on_submit():
            return mech_search_results(form.searchitem.data)
        else:
            select_items = db.session.query(Items.name, Items.oem, Items.amount, Items.minamount)

        if addremform.remove.data and addremform.validate_on_submit():
            yeez = addremform.oem.data
            item = db.session.query(Items).filter(Items.oem==yeez).first()
            item.amount = item.amount - addremform.amount.data
            db.session.commit()
            newlog = LogTable(user_id=current_user.id, item=item.oem, amount=-addremform.amount.data)
            db.session.add(newlog)
            db.session.commit()
        elif addremform.add.data and addremform.validate_on_submit():
            yeez = addremform.oem.data
            item = db.session.query(Items).filter(Items.oem==yeez).first()
            item.amount = item.amount + addremform.amount.data
            db.session.commit()
            newlog = LogTable(user_id=current_user.id, item=item.oem, amount=addremform.amount.data)
            db.session.add(newlog)
            db.session.commit()

        return render_template('mechanic/mechanic.html', form=form, select_items=select_items, addremform=addremform)

    @app.route('/mechanic/search')
    @roles_required('Mechanic')
    def mech_search_results(search):
        form = ItemSearchForm()
        addremform = MechChangeAmountForm()
        if addremform.remove.data and addremform.validate_on_submit():
            yeez = addremform.oem.data
            item = db.session.query(Items).filter(Items.oem==yeez).first()
            item.amount = item.amount - addremform.amount.data
            db.session.commit()
            newlog = LogTable(user_id=current_user.id, item=item.oem, amount=-addremform.amount.data)
            db.session.add(newlog)
            db.session.commit()
        elif addremform.add.data and addremform.validate_on_submit():
            yeez = addremform.oem.data
            item = db.session.query(Items).filter(Items.oem==yeez).first()
            item.amount = item.amount + addremform.amount.data
            db.session.commit()
            newlog = LogTable(user_id=current_user.id, item=item.oem, amount=addremform.amount.data)
            db.session.add(newlog)
            db.session.commit()
        if search == '':
            return redirect(url_for('mechanicpage'))
        else:
            adapted_search = '%' + search + '%'
            select_items = db.session.execute(
                "SELECT name, oem, amount FROM item_table WHERE name LIKE :s OR oem LIKE :s",
                {"s": "%" + adapted_search + "%"},
            ).fetchall()
            #select_items = db.session.query(Items.name, Items.oem, Items.amount).filter(or_(Items.name==search, Items.oem==search)).all()
            return render_template('mechanic/view.html', form=form, select_items=select_items, addremform=addremform)

    return app

#Start dev webserver
if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0',port=8080, debug=False, ssl_context=('server.crt', 'server.key'))