#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-01-30 20:53:54
# @Author  : Bayi
# @Link    : https://blog.flywinky.top/
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
import time
import base64
import hmac
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

    def to_dict(self):
        columns = self.__table__.columns.keys()
        result = {}
        for key in columns:
            value = getattr(self, key)
            result[key] = value
        return result


class Admin(db.Model):
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
# name: /[\u4e00-\u9fa5]/
# phone: /^1[34578]\d{9}$/
# class: /[a-zA-Z0-9_\u4e00-\u9fa5]+/
# email: /^\w+@\w+\.\w+$/


# @app.route("/joinus", methods=['POST'])
# def joinus():
#     data = request.get_json(force=True)
#     # data = {'InfoName': '折蓉蓉', 'InfoPho': '13466777707','InfoProfess': '数学学院','InfoCls': '大一','InfoEmail':
#     # '266455@qq.com', 'InfoGroup': ['移动', '运营'], 'InfoPower': '测试'}
#     if data:
#         addGroup = ",".join(data['InfoGroup'])
#         addInfos = hostInfos(
#             name=data['InfoName'],
#             phone=data['InfoPho'],
#             profess=data['InfoProfess'],
#             grade=data['InfoCls'],
#             email=data['InfoEmail'],
#             group=addGroup,
#             power=data['InfoPower']
#         )
#         db.session.add(addInfos)
#         db.session.commit()
#         return jsonify({"status": True})
#     else:
#         return jsonify({"status": False})

#生成token 入参：用户name
# def generate_token(key, expire=3600):
#     ts_str = str(time.time() + expire)
#     ts_byte = ts_str.encode("utf-8")
#     sha1_tshexstr  = hmac.new(key.encode("utf-8"),ts_byte,'sha1').hexdigest() 
#     token = ts_str+':'+sha1_tshexstr
#     b64_token = base64.urlsafe_b64encode(token.encode("utf-8"))
#     return b64_token.decode("utf-8")
# #验证token 入参：用户name 和 token
# def certify_token(key, token):
#     token_str = base64.urlsafe_b64decode(token).decode('utf-8')
#     token_list = token_str.split(':')
#     if len(token_list) != 2:
#         return False
#     ts_str = token_list[0]
#     if float(ts_str) < time.time():
#         # token expired
#         return False
#     known_sha1_tsstr = token_list[1]
#     sha1 = hmac.new(key.encode("utf-8"),ts_str.encode('utf-8'),'sha1')
#     calc_sha1_tsstr = sha1.hexdigest()
#     if calc_sha1_tsstr != known_sha1_tsstr:
#         # token certification failed
#         return False
#     # token certification success
#     return True
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
    return True


@app.route('/api/login', methods=['POST'])
@auth.login_required
def get_auth_token():
    token = g.admin.generate_auth_token()
    return jsonify({'code': 200, 'msg': "登录成功", 'token': token.decode('ascii'), 'name': g.admin.name})


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


@app.route('/api/users/listpage', methods=['GET'])
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
        'code': 200,
        'total': total,
        'page_size': page_size,
        'infos': [u.to_dict() for u in Infos]
    })


@app.route('/api/hostInfo', methods=['GET'])
def get_hostInfo():
    f1 = open("out.json")
    hostinfo = get_host_info(f1.readlines())
    f1.close()
    return jsonify({
        'code': 200,
        'infos': hostinfo
    })


@app.route('/api/delete_once', methods=['GET'])
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


@app.route('/api/attack_log', methods=['GET'])
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


def add_all(data):
    hostinfos = []
    for i in data:
        # print(i)
        hostinfos.append(hostInfos(timestampNanos=i['timestampNanos'], pid=i['pid'], pname=i['pname'],
                                   absolute_file_path=str(i['absolute_file_path']), cwd=i['cwd'], cmdLine=i['cmdLine'], hostName=i['hostName'], hostip=i['hostip'], userId=i['userId'], groupIds=i['groupIds']))
    # print(hostinfos)
    db.session.add_all(hostinfos)
    db.session.commit()


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


if __name__ == '__main__':

    db.drop_all()
    num = 1
    lines = f.readlines()
    f.close()
    total_log = []
    stop = 0
    for i in lines[1:]:

        t = json.loads(i)
        path = []
        log_info = {
            'timestampNanos': '',
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
            # if t['datum']['properties']['ppid'] == '1':
            #     print(num)
            #     print(i)
            #     continue
            log_info['pid'] = t['datum']['properties']['ppid']
            log_info['pname'] = t['datum']['properties']['name']
            if 'cwd' in lis:
                log_info['cwd'] = t['datum']['properties']['cwd']
            else:
                log_info['cwd'] = ''

            log_info['hostName'] = get_host_info(lines)['hostName']
            log_info['hostip'] = get_host_info(lines)['ips'][0]
            for n in lines[-(len(lines)-num+1)::-1]:
                # print(len(lines)-num+1)
                n = json.loads(n)

                if cjson.isExtend(n, 'sequence') == True:

                    log_info['timestampNanos'] = timeStamp(
                        n['datum']['timestampNanos']/1000000)
                    # path.append(n['datum']['predicateObjectPath'])
                    if cjson.isExtend(n, 'predicateObjectPath') == True:
                        if n['datum']['predicateObjectPath']:
                            path.append(n['datum']['predicateObjectPath'])

                    # print(log_info['timestampNanos'])

                    break

                elif 'PRINCIPAL_LOCAL' in cjson.get_json_value(n, 'type'):
                    log_info['userId'] = cjson.get_json_value(n, 'userId')[0]
                    log_info['groupIds'] = str(
                        cjson.get_json_value(n, 'groupIds')[0])

                # if cjson.get_json_value(n,'PRINCIPAL_LOCAL') is not None:
                #     print(n)
            for m in lines[num+1:]:
                m = json.loads(m)

                # print(cjson.get_json_value(m,'PRINCIPAL_LOCAL'))
                if cjson.isExtend(m, 'baseObject') == True:
                    if cjson.isExtend(m, 'path') == True and m['datum']['baseObject']['properties']['path']:
                            path.append(m['datum']['baseObject']['properties']['path'])

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
    app.run(host='0.0.0.0')
