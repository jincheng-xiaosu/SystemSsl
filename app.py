#coding=utf-8
import difflib
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

from wtforms import StringField,SubmitField,IntegerField,TextField,BooleanField,PasswordField,TextAreaField,SelectField,SelectMultipleField
from wtforms.validators import DataRequired,Required,Length,Email

#from flask.ext.wtf import Form
#from flask_wtf  import Form
from flask_wtf  import FlaskForm
#from flask_wtf import LoginManager,login_required, login_user,logout_user,UserMixin 
#from flask.ext.login import LoginManager,login_required, login_user,logout_user,UserMixin 
from flask_login import LoginManager,login_required, login_user,logout_user,UserMixin 


from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

import os,subprocess
import sys

from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename
import importlib,sys
from configparser import ConfigParser

config = ConfigParser()
config.read('app.conf')

importlib.reload(sys)

#reload(sys)
#sys.setdefaultencoding('utf8')


NGINX_DIRNAME=config.get("nginx", "nginx_dirname")
debug_flag = True
##########
currFolder = os.path.dirname(os.path.realpath(__file__));
app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY='development key',
    SQLALCHEMY_DATABASE_URI ='sqlite:///' + os.path.join(currFolder, 'data.sqlite')
))
#bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db = SQLAlchemy()
db.init_app(app)

class User(UserMixin,db.Model):
    print("into class User...............")
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    # 密码为128的hash值
    password_hash = db.Column(db.String(128))
    # 增加一列判断是否为管理员
    is_admin = db.Column(db.Boolean,default = False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))


    def __repr__(self):
        return '<User %r>' % self.username

    # password设置property使密码不可直接读，verify_password()判断密码是否正确。
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        print(self.password_hash, password)
        return check_password_hash(self.password_hash, password)


    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.is_admin:
                self.role = Role.query.filter_by(name="Administrator").first()
            if self.role is None:
                self.role = Role.query.filter_by(name="User").first()

    # 用户权限验证
    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        print("is_admin starting....")
        return self.can(Permission.ADMINISTER)

def get_ssl_file():
    dir_path = os.path.dirname(os.path.abspath(__file__))
    ssl_dir = dir_path + "/ssl/"
    file_list=[]
    for  files in os.listdir(ssl_dir):
        if  not  os.path.isdir(ssl_dir+files):
            file_list.append(files)
    return file_list

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

        
class BaseForm(FlaskForm):
    LANGUAGES=['zh']

#class LianyunForm(BaseForm):
#    main_program = BooleanField(u'发主程序',validators = [DataRequired()])
#    main_xml = BooleanField(u'发主配置',validators = [DataRequired()])
#    submit = SubmitField(u'提交')

class LoginForm(BaseForm):
    email = StringField(u'邮箱', validators=[Required(), Length(1, 64),Email()])
    password = PasswordField(u'密码', validators=[Required()])
    #remember_me = BooleanField(u'下次自动登录')
    submit = SubmitField(u'登陆')

class UploadForm(BaseForm):
    files = FileField(u'ssl证书文件', validators=[FileRequired(), FileAllowed(['jpg','jpeg','png','gif','pem','crt','key'])])
    submit = SubmitField('上传')
class CheckForm(BaseForm):
    sslname = StringField('ssl证书文件',validators=[Required()])
    content = TextAreaField()
    submit = SubmitField('提交')
class ReplaceForm(BaseForm):
    get_ssl_file=get_ssl_file()
    filename = SelectMultipleField(u'文件名称', choices=[(key,key ) for value,key in enumerate(get_ssl_file)])
    content = TextAreaField()
    submit = SubmitField('提交')
class ConfigureForm(BaseForm):
    nginxdir = StringField(u'nginx的配置文件路径',validators=[Required()])
    submit = SubmitField('确定')
class XmlForm(BaseForm):
    value = StringField('',validators=[Required()])
    submit = SubmitField('提交')

class PutForm(BaseForm):
    put = StringField('',validators=[Required()])
    submit = SubmitField('提交')

class DeleteForm(BaseForm):
    name = StringField('',validators=[Required()])
    value = StringField('',validators=[Required()])
    submit = SubmitField('提交')

def subprores(command,success_res = u'Execution OK'):
    """执行command，返回状态码
    """
    try:
        #retcode = subprocess.call(command,shell=True)
        ret = subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)
        retMessage = ret.stdout.read()
        retcode = ret.poll()
        if retcode == 0 or retcode == None:
            print(retMessage)
            return success_res + u' 成功'
        else:
            print("Child returned",retcode)
            print(retMessage)
            return success_res + u' 失败'
    except OSError as e:
        print >> (sys.stderr,"Execution failed",e)
        return False
def subproress(command,success_res = u'Execution OK'):
    """执行command，返回状态码
    """
    try:
        #retcode = subprocess.call(command,shell=True)
        ret = subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)
        retMessage = ret.stdout.read()
        retcode = ret.poll()
        if retcode == 0 or retcode == None:
            print(retMessage)
            return retMessage
        else:
            print("Child returned",retcode)
            print(retMessage)
            return retMessage
    except OSError as e:
        print >> (sys.stderr,"Execution failed",e)
        return False


def restart_program():
    python = sys.executable
    os.execl(python, python, * sys.argv)

@app.route('/',methods=['GET','POST'])
@login_required
def index():
    #Form = LianyunForm()
    #main_program =  Form.main_program.data
    #main_xml =  Form.main_xml.data
    Form="yes"
    #config.set("nginx","nginx_dirname","xxxxxx")
    #with open("app.conf","w") as f:
    #    config.write(f)
    
    return render_template('index.html',form=Form)
@login_required
@app.route('/login',  methods=['GET',"POST"])
def login():
    Form = LoginForm()
    if Form.email.data and Form.password.data:
        user = User.query.filter_by(email=Form.email.data).first()
        print(user)
        if user is not None and user.verify_password(Form.password.data):
            login_user(user, False)
            return redirect(request.args.get('next') or url_for('index'))
        flash(u'用户名或密码错误，请重新输入。')
    return render_template('login.html',form = Form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if request.method == 'POST':
        # 保存证书到该目录下的ssl目录中
        filesssl = request.files.get('files')
        filename = secure_filename(filesssl.filename)
        filesssl.save(os.path.join('ssl', filename))
        flash('Upload success.')
        # 更主程序文件，这里有一个bug没有解决；第三步骤步更换ssl证书中，没有做到动态更新form表单，虽然新的证书已经保存到服务器中，但是无法更新form表单的多选框
        # 由于程序开启了debug模式，主程序的代码更新之后会自动重新加载程序，所以有了下面的代码；
        print("1111")
        dir_path = os.path.dirname(os.path.abspath(__file__))
        local_file_name=dir_path+"/"+os.path.basename(__file__)
        flash(local_file_name)
        command_line="sed -i \"s/111/1111/g\" " + local_file_name
        res = subproress(command_line)
        flash(res)
        return redirect(url_for('check'))
    return render_template('upload.html', form = form)

# 获取./ssl/目录下的文件名，返回一个list,提供一个表单的多选框；
def get_ssl_file_name(command_line):
    res = subproress(command_line)
    if len(res) == 0:
        print(u"失败")
    elif len(res.split()) == 1:
        names=res.strip().split()[0][:-1]
        return names
    else:
        flash("ss")

@app.route('/check',  methods=['GET',"POST"])
@login_required
def check():
    Form = CheckForm()
    if request.method == 'POST':
        sslname = Form.sslname.data
        ips_port = Form.content.data.split()
        ips_num=len(ips_port)
        flash(u'检查'+ str(ips_num)+'个ip地址')
        for ips in ips_port:
            ip=ips[:-3]
            port=ips[-2:]
            command_line1 = "ssh -p " + str(port) + " root@"+str(ip) +" \" grep 'crt' " + str(NGINX_DIRNAME) + "|sort -u|grep '"+ str(sslname)+"' | awk '{print \$2}'\""
            command_line2 = "ssh -p " + str(port) + " root@"+str(ip) +" \" grep 'key' " + str(NGINX_DIRNAME) + "|sort -u|grep '"+ str(sslname)+"' | awk '{print \$2}'\""
            print(command_line1)
            print(command_line2)
            crt_names=get_ssl_file_name(command_line1)
            key_names=get_ssl_file_name(command_line2)
            if key_names == None or crt_names == None:
                flash("无法获取证书文件路径，请检查nginx的配置路径，IP地址为："+ip+","+port)
                return render_template('check.html',form=Form)
            crt_names=get_ssl_file_name(command_line1).decode('utf-8')
            key_names=get_ssl_file_name(command_line2).decode('utf-8')
            flash(str(ip)+','+str(port)+','+str(crt_names)+','+str(key_names))
        return redirect(url_for('replace'))
    return render_template('check.html',form=Form)  

@app.route('/replace',  methods=['GET',"POST"])
@login_required
def replace():
    Form = ReplaceForm()
    if request.method == 'POST':
        dir_path = os.path.dirname(os.path.abspath(__file__))
        ssl_files = Form.filename.data
        if  len(ssl_files) != 2:
            flash("请选择两个文件，一个是.crt，一个是.key")
            return render_template('replace.html',form=Form)
        crt_name=difflib.get_close_matches('.crt',ssl_files,1, cutoff=0.3)
        key_name=difflib.get_close_matches('.key',ssl_files,1, cutoff=0.3)
        if len(crt_name) == 0 or len(key_name) == 0:
            flash(u"替换失败，请选择证书文件")
            print(crt_name)
            return render_template('replace.html',form=Form)
        content = Form.content.data.split()
        if len(content) == 0:
            flash("请输入第二步骤产生的信息")
            return render_template('replace.html',form=Form)
        for i in content:
            ips_lists=i.split(",")
            ip=ips_lists[0]
            port=ips_lists[1]
            old_crt_name=difflib.get_close_matches('crt',ips_lists,1, cutoff=0.1)
            old_key_name=difflib.get_close_matches('key',ips_lists,1, cutoff=0.1)
            command_line1 = "scp -P "+ str(port) + " " +dir_path+"/ssl/"+str(crt_name[0]) + " root@" + str(ip)+ ":" + str(old_crt_name[0])
            command_line2 = "scp -P "+ str(port) + " " +dir_path+"/ssl/"+str(key_name[0]) + " root@" + str(ip)+ ":" + str(old_key_name[0])
            res1 = subprores(command_line1)
            res2 = subprores(command_line2)
            if res1 == "Execution OK 成功" and res2 == "Execution OK 成功":
                flash(ip+","+port)
            else:
                flash("证书替换失败，执行命令为："+ command_line1 + "和" +command_line2+"，请检查！")
        return redirect(url_for('reload_http_server'))
    return render_template('replace.html',form=Form)  

@app.route('/reload_http_server', methods=['GET', 'POST'])
@login_required
def reload_http_server():
    Form = ReplaceForm()
    if request.method == 'POST':
        content = Form.content.data.split()
        for i in content:
            ips_lists=i.split(",")
            ip=ips_lists[0]
            port=ips_lists[1]
            command_line = "ssh -p " + str(port) + " root@"+str(ip) + " \"nginx -t \""
            res = subprores(command_line)
            if res == "Execution OK 成功":
                command_line = "ssh -p " + str(port) + " root@"+str(ip) + " \"nginx -s reload \""
                reload_nginx = subprores(command_line)
                if reload_nginx == "Execution OK 成功":
                    flash("执行nginx -s reload成功，完成更新ssl，IP地址为："+ip)
                else:
                    flash("执行nginx -s reload失败，请检查，IP地址为："+ip)
            else:
                flash("执行nginx -t 命令失败，请检查，IP地址为："+ip)
    return render_template('reload_http_server.html', form=Form)

@app.route('/peizhi', methods=['GET', 'POST'])
@login_required
def peizhi():
    Form = ConfigureForm()
    if request.method == 'POST':
        nginxdir = Form.nginxdir.data 
        config.set("nginx","nginx_dirname",nginxdir)
        with open("app.conf","w") as f:
            config.write(f)
        dir_path = os.path.dirname(os.path.abspath(__file__))
        local_file_name=dir_path+"/"+os.path.basename(__file__)
        print("22222")
        command_line="sed -i \"s/22222/222222/g\" " + local_file_name
        res = subprores(command_line)
        print(command_line)
        print(nginxdir)
    return render_template('peizhi.html',form=Form)

if __name__ == '__main__':
    app.run(port=50001,debug=True,host='0.0.0.0')
