#!/usr/bin/env python
# -*- coding: utf-8 -*-
import rules
import os
import re
import requests
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
import socket
import random
import threading
import sys
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





class hostInfos(db.Model):
    '''
    日志信息映射类
    '''
    __tablename__ = 'hostInfos'
    id = db.Column(db.Integer, primary_key=True)
    timestampNanos = db.Column(db.String(64))
    pid = db.Column(db.Text(2000))
    ppid = db.Column(db.Text(2000))
    pname = db.Column(db.Text(2000))
    absolute_file_path = db.Column(db.String(64))
    cwd = db.Column(db.String(120))
    cmdLine = db.Column(db.Text(2000))
    hostName = db.Column(db.Text(2000))
    hostip = db.Column(db.Text(2000))
    userId = db.Column(db.Text(2000))
    groupIds = db.Column(db.Text(2000))

    # 获取主机信息
    def to_dict(self):
        columns = self.__table__.columns.keys()
        result = {}
        for key in columns:
            value = getattr(self, key)
            result[key] = value
        return result


class attackInfos(db.Model):
    '''
    日志信息映射类
    '''
    __tablename__ = 'attackInfos'
    id = db.Column(db.Integer, primary_key=True)
    cmdLine = db.Column(db.String(64))
    hostip = db.Column(db.Text(2000))
    pid = db.Column(db.Text(2000))
    pname = db.Column(db.Text(2000))
    ppid = db.Column(db.String(64))
    type_info = db.Column(db.String(120))
    type_name = db.Column(db.Text(2000))

    # 获取attack信息
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

# 验证password


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

# 登录api


@app.route('/api/login', methods=['POST'])
@auth.login_required
def get_auth_token():

    token = g.admin.generate_auth_token()
    token = {
        'token': token
    }

    return jsonify({'code': 20000, 'data': token, 'name': g.admin.name})


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

# 获取数据


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



# 用户信息拉取api


@app.route('/api/userinfo', methods=['GET'])
@auth.login_required
def get_userInfo():
    token = request.args.get('token', '')
    print(token)
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


# @app.route('/api/login', methods=['POST'])
# def login():
#     data = json.loads(request.get_data(as_text=True))
#     token={
#         'token': 'admin-token'
#     }
#     return jsonify({'code': 20000,'data': token})

# 删除一条日志信息
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

# 简单的入侵检测结果


@app.route('/api/attack_log', methods=['GET'])
@auth.login_required
def get_attack_log():
    try:
        query = db.session.query
        Infos = query(attackInfos).all()
        return jsonify({
            'code': 20000,
            'info': [u.to_dict() for u in Infos]
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


# 添加管理员


def init_admin():
    try:
        admin = Admin(
            name='admin', password='$6$rounds=656000$smq9js2whAy2hEJX$4ZClo/lwmoD.z7Ex/qRyJp7fI3tp6ZOEw/CbU2GuZGVx2RrqU9muN./Ri2c04ESWQv/xZcaq1pz5oXgbP2H2Z/')  # 密码passw0rd
        db.session.add(admin)
        db.session.commit()
    except Exception as e:
        print("add fail")


def add_all(data):
    try:
        hostinfos = []
        for i in data:

            hostinfos.append(hostInfos(timestampNanos=i['timestampNanos'], pid=i['pid'], pname=i['pname'], ppid=i['ppid'],
                                       absolute_file_path=str(i['absolute_file_path']), cwd=i['cwd'], cmdLine=i['cmdLine'], hostName=i['hostName'], hostip=i['hostip'], userId=i['userId'], groupIds=i['groupIds']))
        db.session.add_all(hostinfos)
        db.session.commit()
    except Exception as e:
        print("add fail")


def add_attack(data):
    # try:
    attack = attackInfos(
        pid=data['pid'], ppid=data['ppid'], pname=data['pname'], cmdLine=data['cmdLine'], type_info=data['type_info'], type_name=data['type_name'], hostip=data['hostip']
    )
    db.session.add(attack)
    db.session.commit()
    # except Exception as e:
    #     print("add fail")


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


def analyse():
    time.sleep(2)
    total_data = []
    host_data = {}
    # 创建socket
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 本地信息
    address = ('192.168.1.106', 9091)
    tcp_server_socket.bind(address)
    tcp_server_socket.listen(128)
    recv_subject_process = False
    host = 0
    while True:
        # 等待新的客户端连接
        client_socket, clientAddr = tcp_server_socket.accept()
        while True:
            # 接收对方发送过来的数据
            recv_data = client_socket.recv(2048)  # 接收1024个字节
            if recv_data:
                total_log = []
                j = recv_data.decode('gbk')
                total_data.append(j.strip())

                # sys.stdout.write(str(len(total_data))+"\n")
                cjson = checkJSON()
                t = json.loads(j.strip())

                if host == 0:
                    try:
                        host_data = get_host_info(total_data)
                        host = 1
                    except Exception as e:
                        host_data['hostName'] = '未知'
                        host_data['ips'] = ['未知']

                if 'SUBJECT_PROCESS' in cjson.get_json_value(t, 'type'):
                    recv_subject_process = True

                    break
                if recv_subject_process and cjson.isExtend(t, 'sequence'):
                    recv_subject_process = False
                    path = []
                    lis = cjson.getKeys(t)
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
                    if cjson.isExtend(t, 'predicateObjectPath') == True and t['datum']['predicateObjectPath']:
                        path.append(t['datum']['predicateObjectPath'])
                    # if log_info['timestampNanos'] == '':
                    #     if cjson.isExtend(t, 'timestampNanos') == True:
                        # log_info['timestampNanos'] = timeStamp(
                        #     cjson.get_json_value(t, 'timestampNanos')[0]/1000000)
                    # sys.stdout.write(log_info['timestampNanos'])
                    log_info['timestampNanos'] = timeStamp(
                        cjson.get_json_value(t, 'timestampNanos')[0]/1000000)

                    is_subject_process = False
                    for u in total_data[-(len(total_data)-total_data.index(j.strip()))-1::-1]:
                        u = json.loads(u)
                        if cjson.isExtend(u, 'sequence'):
                            if log_info['timestampNanos'] == '':

                                log_info['timestampNanos'] = timeStamp(
                                    u['datum']['timestampNanos']/1000000)
                                # path.append(n['datum']['predicateObjectPath'])
                                if cjson.isExtend(u, 'predicateObjectPath') == True:
                                    if u['datum']['predicateObjectPath']:
                                        path.append(
                                            u['datum']['predicateObjectPath'])

                            break
                        if cjson.isExtend(u, 'baseObject') == True and is_subject_process == False:
                            if cjson.isExtend(u, 'path') == True and u['datum']['baseObject']['properties']['path']:
                                path.append(u['datum']['baseObject']
                                            ['properties']['path'])

                        if 'SUBJECT_PROCESS' in cjson.get_json_value(u, 'type'):
                            is_subject_process = True
                            if log_info['timestampNanos'] and u['datum']['startTimestampNanos'] != 0:
                                log_info['timestampNanos'] = timeStamp(
                                    u['datum']['startTimestampNanos']/1000000)
                            log_info['cmdLine'] = u['datum']['cmdLine'] or ''
                            log_info['pname'] = u['datum']['properties']['name']
                            log_info['pid'] = u['datum']['cid']
                            log_info['ppid'] = u['datum']['properties']['ppid'] or ''
                            if cjson.isExtend(u, 'cwd') == True:
                                log_info['cwd'] = u['datum']['properties']['cwd']

                            log_info['hostName'] = host_data['hostName']
                            log_info['hostip'] = host_data['ips'][0]

                        if 'PRINCIPAL_LOCAL' in cjson.get_json_value(u, 'type'):
                            log_info['userId'] = cjson.get_json_value(u, 'userId')[
                                0]
                            log_info['groupIds'] = str(
                                cjson.get_json_value(u, 'groupIds')[0])
                            # elif cjson.isExtend(n, 'baseObject') == True and cjson.isExtend(n, 'pid'):
                            #     log_info['pid'] = n['datum']['baseObject']['properties']['pid']
                            #     break

                            # if cjson.get_json_value(n,'PRINCIPAL_LOCAL') is not None:
                            #     print(n)

                    log_info['absolute_file_path'] = list(set(path))

                    total_log.append(log_info)

                    total_log = list_dict_duplicate_removal(total_log)

                    add_all(total_log)

                    attack_info = {
                        'pid': '',
                        'ppid': '',
                        'pname': '',
                        'hostip': '',
                        'type_name': '',
                        'type_info': '',
                        'cmdLine': ''
                    }
                    cmdLine = log_info.get('cmdLine')
                    if cmdLine:

                        hostip = log_info.get('hostip')
                        pid = log_info.get('pid')
                        ppid = log_info.get('ppid')
                        pname = log_info.get('pname')
                        defender = Defender(cmdLine)
                        get_rule = defender.run()
                        if get_rule:
                            type_name = get_rule.get('type')
                            type_info = get_rule.get('type_info')
                            attack_info['cmdLine'] = cmdLine
                            attack_info['pid'] = pid
                            attack_info['ppid'] = ppid
                            attack_info['pname'] = pname
                            attack_info['hostip'] = hostip
                            attack_info['type_name'] = type_name
                            attack_info['type_info'] = type_info
                            add_attack(attack_info)
                            attack_log.append(attack_info)

            else:
                break

        client_socket.close()

    tcp_server_socket.close()
    return "hello"


if __name__ == '__main__':

    db.drop_all()
    db.create_all()
    init_admin()
    t = threading.Thread(target=analyse)
    t.start()
    app.run(host='0.0.0.0', debug=False, threaded=True)
    t.join()
