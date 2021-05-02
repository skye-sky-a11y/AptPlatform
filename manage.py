#!/usr/bin/env python
# -*- coding: utf-8 -*-
import rules
import os
import re
import json
import jsonpath
import time
from functools import reduce
from defender import Defender
from flask import Flask, g, jsonify, make_response, request
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from passlib.apps import custom_app_context

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# r'/*' 是通配符，让本服务器所有的 URL 都允许跨域请求
CORS(app, resources=r'/*')
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_RECORD_QUERIES'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'data.sqlite')

db = SQLAlchemy(app)
auth = HTTPBasicAuth()
CSRF_ENABLED = True
app.debug = True
app.config['JSON_AS_ASCII'] = False

f = open("out.json")
attack_log = []


class hostInfos(db.Model):
    '''
    日志信息映射类
    '''
    __tablename__ = 'hostInfos'
    id = db.Column(db.Integer, primary_key=True)
    timestampNanos = db.Column(db.String(64))
    pid = db.Column(db.Text(2000))
    pname = db.Column(db.Text(2000))
    absolute_file_path = db.Column(db.String(64))
    cwd = db.Column(db.String(120))
    cmdLine = db.Column(db.Text(2000))
    hostName = db.Column(db.Text(2000))
    hostip = db.Column(db.Text(2000))
    userId = db.Column(db.Text(2000))
    groupIds = db.Column(db.Text(2000))

    #获取主机信息
    def to_dict(self):
        columns = self.__table__.columns.keys()
        result = {}
        for key in columns:
            value = getattr(self, key)
            result[key] = value
        return result


class Admin(db.Model):
    '''
    管理员表
    '''
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), index=True)
    password = db.Column(db.String(128))

    # 密码加密
    def hash_password(self, password):
        self.password = custom_app_context.encrypt(password)

    # 密码解析
    def verify_password(self, password):
        return custom_app_context.verify(password, self.password)

    # 获取token，有效时间10min
    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    # 解析token，确认登录的用户身份
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        admin = Admin.query.get(data['id'])
        return admin


class checkJSON(object):
    '''
    遍历json所有key
    '''
    def getKeys(self, data):
        keysAll_list = []

        def getkeys(data):  # 遍历json所有key
            if (type(data) == type({})):
                keys = data.keys()
                for key in keys:
                    value = data.get(key)
                    if (type(value) != type({}) and type(value) != type([])):
                        keysAll_list.append(key)
                    elif (type(value) == type({})):
                        keysAll_list.append(key)
                        getkeys(value)
                    elif (type(value) == type([])):
                        keysAll_list.append(key)
                        for para in value:
                            if (type(para) == type({}) or type(para) == type([])):
                                getkeys(para)
                            else:
                                keysAll_list.append(para)
        getkeys(data)
        return keysAll_list

    def isExtend(self, data, tagkey):  # 检测目标字段tagkey是否在data(json数据)中
        if(type(data) != type({})):
            print('please input a json!')
        else:
            key_list = self.getKeys(data)
            for key in key_list:
                if(key == tagkey):
                    return True
        return False

    def get_json_value(self, json_data, key_name):
        '''获取到json中任意key的值,结果为list格式'''
        key_value = jsonpath.jsonpath(
            json_data, '$..{key_name}'.format(key_name=key_name))
        # key的值不为空字符串或者为empty（用例中空固定写为empty）返回对应值，否则返回empty

        return key_value

#验证password
@auth.verify_password
def verify_password(name_or_token, password):
    if not name_or_token:
        return False
    name_or_token = re.sub(r'^"|"$', '', name_or_token)
    admin = Admin.verify_auth_token(name_or_token)
    if not admin:
        admin = Admin.query.filter_by(name=name_or_token).first()
        if not admin or not admin.verify_password(password):
            return False
    g.admin = admin
    print(g.admin.name)
    return True

#登录api
@app.route('/api/login', methods=['POST'])
@auth.login_required
def get_auth_token():

    token = g.admin.generate_auth_token()
    token = {
        'token': token
    }
<<<<<<< HEAD
    return jsonify({'code': 20000, 'data': token, 'name': g.admin.name})
=======
    return jsonify({'code': 20000, 'data': token,'name': g.admin.name})
>>>>>>> 63dfc8db1d33b65b45b0c7e027f643ea00a18e36
    # return jsonify({'code': 20000, 'msg': "登录成功", 'token': token.decode('ascii'), 'name': g.admin.name})


@app.route('/api/setpwd', methods=['POST'])
@auth.login_required
def set_auth_pwd():
    data = json.loads(str(request.data, encoding="utf-8"))
    admin = Admin.query.filter_by(name=g.admin.name).first()
    if admin and admin.verify_password(data['oldpass']) and data['confirpass'] == data['newpass']:
        admin.hash_password(data['newpass'])
        return jsonify({'code': 200, 'msg': "密码修改成功"})
    else:
        return jsonify({'code': 500, 'msg': "请检查输入"})

#获取数据
@app.route('/api/users/listpage', methods=['GET'])
@auth.login_required
def get_user_list():
    page_size = request.args.get('limit', 20, type=int)
    page = request.args.get('page', 1, type=int)
    sort = request.args.get('sort', '')
    pid = request.args.get('pid', '')
    query = db.session.query
    if pid:
        Infos = query(hostInfos).filter(
            hostInfos.pid.like('%{}%'.format(pid)))
    else:
        Infos = query(hostInfos)
    if sort:
        Infos = Infos.order_by(text(sort))
    total = Infos.count()
    if not page:
        Infos = Infos.all()
    else:
        Infos = Infos.offset((page - 1) * page_size).limit(page_size).all()
    return jsonify({
        'code': 20000,
        'total': total,
        'page_size': page_size,
        'infos': [u.to_dict() for u in Infos]
    })


#获取主机信息
@app.route('/api/hostInfo', methods=['GET'])
@auth.login_required
def get_hostInfo():
    f1 = open("out.json")
    hostinfo = get_host_info(f1.readlines())
    f1.close()
    return jsonify({
        'code': 20000,
        'infos': hostinfo
    })

#用户信息拉取api
@app.route('/api/userinfo', methods=['GET'])
@auth.login_required
def get_userInfo():
    token = request.args.get('token', '')
    users = {
        'admin': {
            'roles': ['admin'],
            'introduction': 'I am a super administrator',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Super Admin'
        },
        'editor': {
            'roles': ['editor'],
            'introduction': 'I am an editor',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Normal Editor'
        }
    }
    admin = Admin.verify_auth_token(token)
    if admin:
        if admin.name == 'admin':
            infos = users['admin']
        else:
            infos = users['editor']
        return jsonify({
            'code': 20000,
            'data': infos
        })
    else:
        return jsonify({
            'code': 50000,
            'data': 'something wrong'
        })


<<<<<<< HEAD
=======
@app.route('/api/userinfo', methods=['GET'])
@auth.login_required
def get_userInfo():
    token = request.args.get('token', '')
    users = {
        'admin': {
            'roles': ['admin'],
            'introduction': 'I am a super administrator',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Super Admin'
        },
        'editor': {
            'roles': ['editor'],
            'introduction': 'I am an editor',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Normal Editor'
        }
    }
    admin = Admin.verify_auth_token(token)
    if admin:
        if admin.name == 'admin':
            infos = users['admin']
            print(infos)
        else:
            infos = users['editor']
        print(infos)
        return jsonify({
            'code': 20000,
            'data': infos
        })
    else:
        return jsonify({
            'code': 50000,
            'data': 'something wrong'
        })


>>>>>>> 63dfc8db1d33b65b45b0c7e027f643ea00a18e36
# @app.route('/api/login', methods=['POST'])
# def login():
#     data = json.loads(request.get_data(as_text=True))
#     token={
#         'token': 'admin-token'
#     }
#     return jsonify({'code': 20000,'data': token})

<<<<<<< HEAD
#删除一条日志信息
=======

>>>>>>> 63dfc8db1d33b65b45b0c7e027f643ea00a18e36
@app.route('/api/delete_once', methods=['GET'])
@auth.login_required
def delete_once():
    try:
        delete_id = request.args.get('delete_id')
        query = db.session.query
        delete_info = query(hostInfos).filter(
            hostInfos.id == int(delete_id)).first()
        db.session.delete(delete_info)
        db.session.commit()
        return jsonify({
            'code': 20000,
            'info': "删除成功"
        })
    except Exception as e:
        return jsonify({
            'code': 50000,
            'info': "删除失败"
        })

#简单的入侵检测结果
@app.route('/api/attack_log', methods=['GET'])
@auth.login_required
def get_attack_log():
    try:
        return jsonify({
            'code': 20000,
            'info': attack_log
        })
    except Exception as e:
        return jsonify({
            'code': 50000,
            'info': "删除失败"
        })


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


def get_host_info(lines):  # 获取主机信息

    t = json.loads(lines[0])
    host_info = {}
    host_info['hostName'] = t['datum']['hostName']
    host_info['osDetails'] = t['datum']['osDetails']
    host_info['hostType'] = t['datum']['hostType']
    host_info['interfaces'] = t['datum']['interfaces']
    host_info['serial number'] = t['datum']['hostIdentifiers'][0]['idValue']
    ips = []
    for i in t['datum']['interfaces']:
        for ip in i['ipAddresses']:
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip) and ip != '127.0.0.1':
                ips.append(ip)

        host_info['ips'] = ips
    return host_info

#添加日志信息
def add_all(data):
    try:
        hostinfos = []
        for i in data:
<<<<<<< HEAD
            hostinfos.append(hostInfos(timestampNanos=i['timestampNanos'], pid=i['pid'], pname=i['pname'],
                                       absolute_file_path=str(i['absolute_file_path']), cwd=i['cwd'], cmdLine=i['cmdLine'], hostName=i['hostName'], hostip=i['hostip'], userId=i['userId'], groupIds=i['groupIds']))
        db.session.add_all(hostinfos)
        admin = Admin(
            name='admin', password='$6$rounds=656000$smq9js2whAy2hEJX$4ZClo/lwmoD.z7Ex/qRyJp7fI3tp6ZOEw/CbU2GuZGVx2RrqU9muN./Ri2c04ESWQv/xZcaq1pz5oXgbP2H2Z/') #密码passw0rd
=======
            # print(i)
            hostinfos.append(hostInfos(timestampNanos=i['timestampNanos'], pid=i['pid'], pname=i['pname'],
                                    absolute_file_path=str(i['absolute_file_path']), cwd=i['cwd'], cmdLine=i['cmdLine'], hostName=i['hostName'], hostip=i['hostip'], userId=i['userId'], groupIds=i['groupIds']))
        # print(hostinfos)
        db.session.add_all(hostinfos)
        admin = Admin(name='admin',password='$6$rounds=656000$smq9js2whAy2hEJX$4ZClo/lwmoD.z7Ex/qRyJp7fI3tp6ZOEw/CbU2GuZGVx2RrqU9muN./Ri2c04ESWQv/xZcaq1pz5oXgbP2H2Z/')

>>>>>>> 63dfc8db1d33b65b45b0c7e027f643ea00a18e36
        db.session.add(admin)
        db.session.commit()
    except Exception as e:
        print("add fail")


def timeStamp(timeNum):		# 输入毫秒级的时间，转出正常格式的时间
    timeStamp = float(timeNum/1000)
    timeArray = time.localtime(timeStamp)
    otherStyleTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    return otherStyleTime
    # print(otherStyleTime)
    # 2019-08-14 10:40:06


def list_dict_duplicate_removal(data):  # 去重 list
    def run_function(x, y): return x if y in x else x + [y]
    return reduce(run_function, [[], ] + data)
# def bytetoint(byte):
#     return reduce(lambda x, y: (x << 8) + y, byte)


def analyse(f, attack_log):
    db.drop_all()
    num = 1
    lines = f.readlines()
    f.close()
    total_log = []
    for i in lines[1:]:

        t = json.loads(i)
        path = []
        log_info = {
            'timestampNanos': '',
            'ppid': '',
            'cmdLine': '',
            'pid': '',
            'pname': '',
            'absolute_file_path': '',
            'cwd': '',
            'hostName': '',
            'hostip': '',
            'userId': '',
            'groupIds': ''
        }

        cjson = checkJSON()
        lis = cjson.getKeys(t)

        # try:
        if 'SUBJECT_PROCESS' in cjson.get_json_value(t, 'type'):
            log_info['timestampNanos'] = timeStamp(
                t['datum']['startTimestampNanos']/1000000) if t['datum']['startTimestampNanos'] != 0 else 0
            log_info['cmdLine'] = t['datum']['cmdLine'] or ''
            log_info['pname'] = t['datum']['properties']['name']
            if 'cwd' in lis:
                log_info['cwd'] = t['datum']['properties']['cwd']
            else:
                log_info['cwd'] = ''

            log_info['hostName'] = get_host_info(lines)['hostName']
            log_info['hostip'] = get_host_info(lines)['ips'][0]
            for n in lines[-(len(lines)-num+1)::-1]:

                n = json.loads(n)

                if cjson.isExtend(n, 'sequence') == True and log_info['timestampNanos'] == 0:

                    log_info['timestampNanos'] = timeStamp(
                        n['datum']['timestampNanos']/1000000)
                    # path.append(n['datum']['predicateObjectPath'])
                    if cjson.isExtend(n, 'predicateObjectPath') == True:
                        if n['datum']['predicateObjectPath']:
                            path.append(n['datum']['predicateObjectPath'])

                elif 'PRINCIPAL_LOCAL' in cjson.get_json_value(n, 'type'):
                    log_info['userId'] = cjson.get_json_value(n, 'userId')[0]
                    log_info['groupIds'] = str(
                        cjson.get_json_value(n, 'groupIds')[0])
                elif cjson.isExtend(n, 'baseObject') == True and cjson.isExtend(n, 'pid'):
                    log_info['pid'] = n['datum']['baseObject']['properties']['pid']
                    break

                # if cjson.get_json_value(n,'PRINCIPAL_LOCAL') is not None:
                #     print(n)
            for m in lines[num+1:]:
                m = json.loads(m)

                # print(cjson.get_json_value(m,'PRINCIPAL_LOCAL'))
                if cjson.isExtend(m, 'baseObject') == True:
                    if cjson.isExtend(m, 'path') == True and m['datum']['baseObject']['properties']['path']:
                        path.append(m['datum']['baseObject']
                                    ['properties']['path'])

                elif log_info['timestampNanos'] == 0:
                    if cjson.isExtend(m, 'timestampNanos') == True:
                        log_info['timestampNanos'] = timeStamp(
                            cjson.get_json_value(m, 'timestampNanos')[0]/1000000)

                elif cjson.isExtend(m, 'sequence') == True:
                    if cjson.isExtend(m, 'predicateObjectPath') == True and m['datum']['predicateObjectPath']:
                        path.append(m['datum']['predicateObjectPath'])
                        break
                    else:
                        break

            log_info['absolute_file_path'] = list(set(path))

            total_log.append(log_info)

        num = num + 1
    total_log = list_dict_duplicate_removal(total_log)
    for i in total_log:
        attack_info = {
            'pid': '',
            'pname': '',
            'hostip': '',
            'type_name': '',
            'type_info': '',
            'cmdLine': ''
        }
        cmdLine = i.get('cmdLine')
        if cmdLine:
            hostip = i.get('hostip')
            pid = i.get('pid')
            pname = i.get('pname')
            defender = Defender(cmdLine)
            get_rule = defender.run()
            if get_rule:
                type_name = get_rule.get('type')
                type_info = get_rule.get('type_info')
                attack_info['cmdLine'] = cmdLine
                attack_info['pid'] = pid
                attack_info['pname'] = pname
                attack_info['hostip'] = hostip
                attack_info['type_name'] = type_name
                attack_info['type_info'] = type_info
                attack_log.append(attack_info)
    db.create_all()
    add_all(total_log)

if __name__ == '__main__':

    analyse(f, attack_log)
    app.run(host='0.0.0.0')
