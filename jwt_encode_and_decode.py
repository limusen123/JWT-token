# 自制JWT-token
import json
import hmac
import time
import base64


class JwtMake:
    # 传入用户名、过期时间、签名
    def __init__(self, username, exp, key):
        self.username = username
        self.exp = exp
        self.key = key

    # 签发token
    def jwt_encode(self):
        # 生成header
        header = {'alg': 'HS256', 'typ': 'JWT'}
        # separators=(',', ':')：代表key和val间用':'连接，key和key之间使用','连接（目的就是去掉多余的空格）
        # sort_keys=True：为了规避掉字典的无序带来的问题，该参数的目的就是让字典的顺序固定。
        header_j = json.dumps(header, separators=(',', ':'), sort_keys=True)
        header_bs = JwtMake.b64encode(header_j.encode())
        # 生成payload
        payload = {'username': self.username, 'exp': int(time.time() + self.exp)}
        payload_j = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload_bs = JwtMake.b64encode(payload_j.encode())
        # 生成sign
        # 判断传入的key是否为字节串
        if isinstance(self.key, str):
            self.key = self.key.encode()
        hmac_object = hmac.new(self.key, header_bs + b'.' + payload_bs, digestmod='SHA256')
        sign_str = hmac_object.digest()
        sign_bs = JwtMake.b64encode(sign_str)
        return header_bs + b'.' + payload_bs + b'.' + sign_bs

    # 验证token
    def jwt_decode(self, token):
        header_bs, payload_bs, sign_bs = token.split(b'.')
        # 判断两部分：1.判断签名是否正确。2.判断是否过期
        # 如果判断通过则返回用户名，如果不通过则raise报错
        if isinstance(self.key, str):
            self.key = self.key.encode()
        sign_new_obj = hmac.new(self.key, header_bs + b'.' + payload_bs, digestmod='SHA256')
        sign_new = JwtMake.b64encode(sign_new_obj.digest())
        if sign_new != sign_bs:
            raise JwtError('The token is valid')
        # 判断是否过期
        payload_b = JwtMake.b64decode(payload_bs)
        payload_j = payload_b.decode()
        payload = json.loads(payload_j)
        now_time = time.time()
        exp_time = payload['exp']
        if now_time > exp_time:
            raise JwtError('The token is expired')
        return payload['username']

    # 进行base64编码并去掉'='
    @staticmethod
    def b64encode(s):
        s_bs = base64.urlsafe_b64encode(s)
        return s_bs.replace(b'=', b'')

    # 将去掉的'='加回来并进行base64解码
    @staticmethod
    def b64decode(bs):
        bs_len = len(bs)
        add_num = 4 - (bs_len % 4)
        return base64.urlsafe_b64decode(bs + add_num * b'=')


# 自定义异常类，用于token验证
class JwtError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return '<JwtError error %s>' % self.msg


if __name__ == '__main__':
    jwt = JwtMake('my_name', 200, '123456')
    token = jwt.jwt_encode()
    time.sleep(3)
    name = jwt.jwt_decode(token)
    print(token)
    print(name)
